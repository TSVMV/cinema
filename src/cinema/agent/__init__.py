"""Controlled agent layer: a fixed tool set for forensic Q&A over a trace.

The agent never gets a shell. It can only call the tools in
:mod:`cinema.agent.tools`, each of which executes against the recording for
real and returns recorded data. Decisions come from a ``Decider``; the fake
``ScriptedDecider`` used in tests only picks tools, never fabricates results.
"""
