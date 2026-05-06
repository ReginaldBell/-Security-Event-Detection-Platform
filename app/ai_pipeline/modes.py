# The pipeline is tested in three security postures so the same attack can be
# observed with no guardrails, light guardrails, and strict guardrails.
OFF = "OFF"
PARTIAL = "PARTIAL"
FULL = "FULL"

# Scripts iterate this list in order to tell a clear before/after story: first
# the vulnerable baseline, then a partial defense, then the full control set.
ALL_MODES = [OFF, PARTIAL, FULL]
