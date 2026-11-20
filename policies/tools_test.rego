package aigov_tools_test

import data.aigov
import data.aigov.tool_calls

bot := {"name": "support-bot", "risk_tier": "limited"}

# --- Tools offered in the request ---

test_approved_tools_allowed if {
	count(aigov.deny) == 0 with input as {"system": bot, "tools": ["get_order_status"], "messages": []}
}

test_unapproved_tool_denied if {
	aigov.deny["tool \"delete_customer\" is not approved for support-bot"] with input as {
		"system": bot, "tools": ["delete_customer"], "messages": [],
	}
}

test_unlisted_system_gets_no_tools if {
	count(aigov.deny) == 1 with input as {
		"system": {"name": "new-bot", "risk_tier": "minimal"}, "tools": ["get_order_status"], "messages": [],
	}
}

# --- Tool calls in the response ---

test_normal_call_allowed if {
	result := tool_calls with input as {
		"system": bot,
		"tool_calls": [{"name": "get_order_status", "arguments": {"order_id": "A-1"}}],
	}
	count(result.deny) == 0
	count(result.hold) == 0
}

test_invented_tool_denied if {
	count(tool_calls.deny) == 1 with input as {
		"system": bot, "tool_calls": [{"name": "drop_database", "arguments": {}}],
	}
}

test_broken_arguments_denied if {
	count(tool_calls.deny) == 1 with input as {
		"system": bot, "tool_calls": [{"name": "get_order_status", "arguments": null}],
	}
}

test_small_refund_allowed if {
	count(tool_calls.hold) == 0 with input as {
		"system": bot, "tool_calls": [{"name": "issue_refund", "arguments": {"amount": 40}}],
	}
}

test_large_refund_held if {
	tool_calls.hold["refunds over 100 EUR need human review"] with input as {
		"system": bot, "tool_calls": [{"name": "issue_refund", "arguments": {"amount": 250}}],
	}
}

test_high_risk_calls_held if {
	count(tool_calls.hold) == 1 with input as {
		"system": {"name": "loan-agent", "risk_tier": "high"},
		"tool_calls": [{"name": "get_credit_report", "arguments": {"applicant": "[EMAIL_1]"}}],
	}
}