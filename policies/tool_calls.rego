# Rules for the tool calls a model makes in its response, checked before
# the response reaches the AI agent that would carry them out.
#
# The gateway evaluates data.aigov.tool_calls and reads:
#   deny - reasons to stop the response
#   hold - reasons to pause it for human review
#
# input contains:
#   system:     {name, owner, risk_tier}
#   model
#   tool_calls: [{name, arguments}]  (arguments is the parsed JSON object,
#                                     or null if it was not valid JSON)
#
# Reasons end up in the audit log, so they must not quote argument values:
# those can contain personal data.
package aigov.tool_calls

import data.aigov.allowed_tools

# Models sometimes call tools they were never given. The request was
# already checked, so this is defence in depth.
deny contains msg if {
	some call in input.tool_calls
	not call.name in object.get(allowed_tools, input.system.name, set())
	msg := sprintf("the model called %q, which is not approved for %s", [call.name, input.system.name])
}

deny contains msg if {
	some call in input.tool_calls
	not is_object(call.arguments)
	msg := sprintf("the arguments for %q are not a valid JSON object", [call.name])
}

# Money leaving the company above a threshold needs a person to agree.
hold contains msg if {
	some call in input.tool_calls
	call.name == "issue_refund"
	call.arguments.amount > 100
	msg := "refunds over 100 EUR need human review"
}

# High-risk systems: every action the model asks for is reviewed.
hold contains msg if {
	input.system.risk_tier == "high"
	count(input.tool_calls) > 0
	msg := "tool calls from high-risk AI systems need human review (AI Act Art. 14)"
}