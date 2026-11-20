# Which tools each AI system may give the model (OpenAI "tools" or the
# older "functions"). input.tools holds the tool names in the request.
#
# A system that is not listed may not use tools at all: an AI agent's
# abilities have to be approved, not assumed.
package aigov

allowed_tools := {
	"support-bot": {"search_help_center", "get_order_status", "issue_refund"},
	"loan-agent": {"get_credit_report"},
}

deny contains msg if {
	some name in input.tools
	not name in object.get(allowed_tools, input.system.name, set())
	msg := sprintf("tool %q is not approved for %s", [name, input.system.name])
}