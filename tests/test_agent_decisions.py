"""Agent role routing and tool-result interpretation with a scripted LLM.

No live model calls, devices, or external CLIs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import maya.tools  # noqa: F401
from maya.agents.maya_agent import MayaAgent
from maya.agents.state import AgentState
from maya.decision.broker import get_decision_broker
from maya.llm.llm import LLMResponse

MANIFEST = Path(__file__).parent / "fixtures" / "sample_android_manifest.xml"


class ScriptedLLM:
    def __init__(self, scripts: list[str]) -> None:
        self.scripts = list(scripts)
        self.prompts: list[list[dict[str, str]]] = []

    async def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        del temperature, max_tokens
        self.prompts.append(list(messages))
        if not self.scripts:
            raise AssertionError("scripted LLM ran out of responses")
        return LLMResponse(
            content=self.scripts.pop(0),
            model="mock/scripted",
            finish_reason="stop",
            usage={"prompt_tokens": 1, "completion_tokens": 1},
        )


def make_agent(llm: ScriptedLLM, role: str = "static") -> MayaAgent:
    return MayaAgent(
        task="Review the fixture manifest and record exported components.",
        name="decision-tester",
        role=role,
        llm=llm,
        sandbox_mode="host",
        decision_mode="auto_only",
        decision_timeout_seconds=1,
        max_iterations=4,
    )


def test_role_routing_selects_modules_and_skills() -> None:
    static_agent = MayaAgent(task="static", role="static")
    dynamic_agent = MayaAgent(task="dynamic", role="dynamic")
    api_agent = MayaAgent(task="api", role="api")
    unknown_agent = MayaAgent(task="unknown", role="not-a-role")
    root_agent = MayaAgent(task="root", role="root")

    assert static_agent._role_modules() == {
        "reporting",
        "agents_graph",
        "skills_runtime",
        "shared_context",
        "apk_tool",
        "mobsf_tool",
        "terminal",
    }
    assert "frida_tool" not in static_agent._role_modules()
    assert "objection_tool" not in static_agent._role_modules()
    assert static_agent._role_default_skills() == ["static_analyzer"]

    assert "frida_tool" in dynamic_agent._role_modules()
    assert "objection_tool" in dynamic_agent._role_modules()
    assert "mobsf_tool" not in dynamic_agent._role_modules()
    assert dynamic_agent._role_default_skills() == ["dynamic_tester"]

    assert "caido_tool" in api_agent._role_modules()
    assert "apk_tool" not in api_agent._role_modules()
    assert api_agent._role_default_skills() == ["api_discoverer"]

    assert unknown_agent._role_modules() == root_agent._role_modules()
    assert unknown_agent._role_default_skills() == []
    assert root_agent._role_default_skills() == ["root_orchestrator"]

    static_prompt = static_agent.build_system_prompt()
    dynamic_prompt = dynamic_agent.build_system_prompt()
    assert "Your role is static." in static_prompt
    assert "<apk_tool_tools>" in static_prompt
    assert 'name="analyze_manifest"' in static_prompt
    assert "static_analyzer" in static_prompt
    assert "<frida_tool_tools>" not in static_prompt
    assert "<objection_tool_tools>" not in static_prompt
    assert "Your role is dynamic." in dynamic_prompt
    assert "<frida_tool_tools>" in dynamic_prompt
    assert "<objection_tool_tools>" in dynamic_prompt
    assert "<mobsf_tool_tools>" not in dynamic_prompt


def test_manifest_result_creates_exported_leads_and_is_fed_back() -> None:
    llm = ScriptedLLM(
        [
            f'<invoke name="analyze_manifest"><param name="manifest_path">{MANIFEST}</param></invoke>',
            "The manifest has been recorded. No further tool call.",
        ]
    )
    agent = make_agent(llm)

    stopped = asyncio.run(agent._process_iteration())
    assert stopped is False
    titles = {lead["title"] for lead in agent.state.leads}
    assert titles == {
        "Exported activity: .MainActivity",
        "Exported provider: .InsecureProvider",
    }
    assert all(lead["state"] == "new" for lead in agent.state.leads)
    assert agent.state.loop_stage == "enumerate"
    assert agent.state.tool_call_count == 1
    assert agent.state.tool_errors == 0
    observations = [msg["content"] for msg in agent.state.messages if msg["role"] == "user"]
    assert any('tool="analyze_manifest"' in msg and 'status="success"' in msg for msg in observations)

    agent.state.iteration_count = 1
    stopped = asyncio.run(agent._process_iteration())
    assert stopped is False
    assert agent.state.loop_stage == "validate"
    assert agent.state.tool_call_count == 1
    feedback = "\n".join(msg["content"] for msg in llm.prompts[1])
    assert "analyze_manifest" in feedback
    assert ".MainActivity" in feedback
    assert ".SecretActivity" not in "\n".join(lead["title"] for lead in agent.state.leads)


def test_plain_text_does_not_execute_tools() -> None:
    llm = ScriptedLLM(["The fixture has two exported components. I will record that and stop."])
    agent = make_agent(llm)

    stopped = asyncio.run(agent._process_iteration())

    assert stopped is False
    assert agent.state.tool_call_count == 0
    assert agent.state.leads == []
    assert agent.state.messages[-1]["role"] == "assistant"
    assert "two exported components" in agent.state.messages[-1]["content"]


def test_finish_scan_stops_the_iteration() -> None:
    llm = ScriptedLLM(
        [
            "<function=finish_scan>"
            "<parameter=summary>Recorded two exported components from the fixture.</parameter>"
            "</function>"
        ]
    )
    agent = make_agent(llm, role="root")

    stopped = asyncio.run(agent._process_iteration())

    assert stopped is True
    assert any(note.startswith("finish_scan:") for note in agent.state.notes)
    assert agent.state.tool_call_count == 1


def test_unknown_tool_and_missing_args_are_errors() -> None:
    llm = ScriptedLLM(
        [
            "<function=not_a_real_tool><parameter=path>fixture</parameter></function>",
            "<function=analyze_manifest></function>",
        ]
    )
    agent = make_agent(llm)

    assert asyncio.run(agent._process_iteration()) is False
    assert agent.state.tool_errors == 1
    assert agent.state.leads == []
    assert any("Unknown tool: not_a_real_tool" in msg["content"] for msg in agent.state.messages)

    assert asyncio.run(agent._process_iteration()) is False
    assert agent.state.tool_errors == 2
    assert agent.state.leads == []
    assert any("Missing required params for analyze_manifest" in msg["content"] for msg in agent.state.messages)


def test_auto_mode_blocks_high_risk_tool_without_running_it(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def fail_if_called(*_args, **_kwargs):
        calls.append(_args)
        raise AssertionError("subprocess should not run when the decision gate blocks")

    monkeypatch.setattr("maya.tools.proc.subprocess.run", fail_if_called)
    broker = get_decision_broker()
    broker.configure(decision_mode="auto_only", timeout_seconds=1)
    broker.set_ui_handler(None)

    llm = ScriptedLLM(
        [
            "<function=tamper_and_install>"
            "<parameter=decompiled_dir>/tmp/fixture-decoded</parameter>"
            "<parameter=package_name>com.example.app</parameter>"
            "</function>"
        ]
    )
    agent = make_agent(llm, role="root")
    stopped = asyncio.run(agent._process_iteration())

    assert stopped is False
    assert calls == []
    assert agent.state.tool_call_count == 0
    assert agent.state.decision_history[-1]["selected_option"] == "Gather More Evidence"
    assert agent.state.decision_history[-1]["source"] == "auto"
    observations = [msg["content"] for msg in agent.state.messages if msg["role"] == "user"]
    assert any("Execution blocked by decision gate: Gather More Evidence" in msg for msg in observations)


def test_create_agent_parses_skills_and_surfaces_graph_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict] = []

    class RecordingGraph:
        async def create_agent(self, **kwargs):
            captured.append(kwargs)
            return {"status": "error", "message": "max_agents limit reached (7)"}

    monkeypatch.setattr(
        "maya.tools.agents_graph.AgentGraph.instance",
        staticmethod(lambda: RecordingGraph()),
    )

    llm = ScriptedLLM(
        [
            "<function=create_agent>"
            "<parameter=task>Enumerate exported components from the fixture manifest</parameter>"
            "<parameter=name>static-child</parameter>"
            "<parameter=skills>static_analyzer, flutter_analysis</parameter>"
            "</function>"
        ]
    )
    agent = make_agent(llm, role="root")
    stopped = asyncio.run(agent._process_iteration())

    assert stopped is False
    assert len(captured) == 1
    assert captured[0]["name"] == "static-child"
    assert captured[0]["task"] == "Enumerate exported components from the fixture manifest"
    assert captured[0]["skills"] == ["static_analyzer", "flutter_analysis"]
    assert captured[0]["agent_class_name"] == "MayaAgent"
    assert isinstance(captured[0]["parent_state"], AgentState)
    assert captured[0]["parent_state"].agent_id == agent.state.agent_id
    assert any("max_agents limit reached" in msg["content"] for msg in agent.state.messages)


def test_observation_ingest_moves_lead_state_only_on_success() -> None:
    agent = make_agent(ScriptedLLM([]))
    lead = agent.state.add_lead(title="Exported activity: .MainActivity", source="manifest")

    agent._ingest_observation("analyze_manifest", {"error": "manifest not found"})
    assert len(agent.state.leads) == 1

    agent._ingest_observation("verify_frida_attached", {"status": "error", "stdout": ""})
    assert lead["state"] == "new"

    agent._ingest_observation("verify_frida_attached", {"status": "ok", "stdout": "com.example.app"})
    assert lead["state"] == "validated"

    agent._ingest_observation("tamper_and_install", {"status": "error"})
    assert lead["state"] == "validated"

    agent._ingest_observation("tamper_and_install", {"status": "ok"})
    assert lead["state"] == "exploited"

    agent._ingest_observation("report_vulnerability", {"status": "duplicate"})
    assert lead["state"] == "reported"

    before = len(agent.state.leads)
    agent._ingest_observation(
        "report_api_endpoint",
        {"endpoint": {"method": "GET", "url": "https://example.invalid/health"}},
    )
    assert len(agent.state.leads) == before + 1
    assert agent.state.leads[-1]["title"] == "API endpoint GET https://example.invalid/health"
    assert agent.state.leads[-1]["state"] == "new"


def test_progress_nudges_when_stalled_or_repeating() -> None:
    agent = make_agent(ScriptedLLM([]))
    agent.state.iteration_count = 5
    nudge = agent._check_progress()
    assert nudge is not None
    assert "static artifacts" in nudge

    agent.state.findings.append({"title": "backup enabled"})
    assert agent._check_progress() is None

    agent.state.iteration_count = 2
    repeated = "<toolName>analyze_manifest</toolName>"
    for _ in range(5):
        agent.state.add_message("assistant", repeated)
    repeat = agent._check_progress()
    assert repeat is not None
    assert "repeating similar tool calls" in repeat

    agent.state.messages.clear()
    agent.state.add_message("assistant", "<toolName>analyze_manifest</toolName>")
    agent.state.add_message("assistant", "<toolName>report_api_endpoint</toolName>")
    assert agent._check_progress() is None
