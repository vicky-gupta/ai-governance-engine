# Governance rules for every chat request that passes through the gateway.
#
# The gateway evaluates data.aigov and reads three results:
#   deny       - reasons to block the request (any reason blocks)
#   hold       - reasons to pause it for human review
#   max_tokens - the longest answer this request may ask for
#
# input contains:
#   system:     {name, owner, risk_tier}
#   model, provider, region
#   max_tokens: the caller's value (missing if not set)
#   messages:   [{role, text}]  (text is already PII-redacted)
#
# This file is reloaded automatically when it changes. A version with an
# error is rejected and the previous version stays active.
package aigov

# Internal names that must never reach an external model.
blocked_terms := {"project falcon", "salary", "bonus"}

deny contains msg if {
	some m in input.messages
	some term in blocked_terms
	contains(lower(m.text), term)
	msg := sprintf("message mentions blocked term %q", [term])
}

# A high-risk system asking the model to decide on a person's credit
# application. Under GDPR Article 22 and the EU AI Act's human-oversight
# rules (Article 14), a person must make that call.
hold contains msg if {
	input.system.risk_tier == "high"
	some m in input.messages
	m.role == "user"
	regex.match(`(?i)\b(approve|reject|decline)\b.*\b(loan|credit|application)\b`, m.text)
	msg := "credit decisions about a person need human review (GDPR Art. 22, AI Act Art. 14)"
}

# The longest answer each risk tier may request.
default max_tokens := 4096

max_tokens := 1024 if input.system.risk_tier == "high"


# Answers of high-risk systems must be checked before anyone sees them.
# A streamed answer is already on its way while it is written, so it can
# only be checked afterwards.
deny contains msg if {
	some m in input.messages
	some term in blocked_terms
	mentions(m.text, term)
	msg := sprintf("message mentions blocked term %q", [term])
}

# mentions is true if text contains term, however it is written:
# any case, any kind of space (models like the narrow no-break space),
# and with punctuation or markdown in between ("Project **FALCON**",
# "project-falcon").
mentions(text, term) if contains(normalize(text), normalize(term))

# normalize lowercases s and turns every run of characters that are not
# letters or digits into one plain space.
normalize(s) := trim_space(regex.replace(lower(s), `[^\p{L}\p{N}]+`, " "))


# Answers of high-risk systems must be checked before anyone sees them.
# A streamed answer is already on its way while it is written, so it can
# only be checked afterwards.
deny contains msg if {
	input.system.risk_tier == "high"
	input.stream
	msg := "high-risk AI systems may not stream answers: they must be checked before delivery"
}