# ok: HOOK-002
# Session-end gate (Stop hook) is configured in .drako.yaml
# hooks:
#   on_session_end:
#     - name: require-tests-passed
#       script: .drako/hooks/check_tests.py
#       action_on_fail: block
#       timeout_ms: 10000
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Complete user workflow")
