# Project Vision

This document keeps the direction for `privacy-intent` explicit so the project stays privacy-focused instead of drifting into generic web scanning.

## Repository Identity

- Repo: `privacy-intent`
- Working title: `PrivacyIntent`
- Current repository type: privacy-focused web reconnaissance and auditing CLI
- Current role: transparent privacy review engine for browser-visible signals

## Current Framing

PrivacyIntent is strongest when it stays tightly focused on privacy posture and browser-observable evidence.

Its value is in:

- explainable privacy findings
- browser-captured evidence
- practical remediation guidance
- clean local and CI usage

It should not dilute that focus by turning into a generic all-purpose scanner.

## Strategic Focus

- Keep privacy-specific signal quality high.
- Prefer transparent detector logic over opaque risk labels.
- Keep the OSS core useful even as Pro features diverge.

## Practical Direction

Near-term work in this repo should focus on:

- detector tuning and false-positive control
- stronger regression and baseline workflows
- clearer evidence packaging
- preserving the privacy-specific identity of the tool

## Planning Rule

If a feature is primarily about privacy posture in web traffic, keep it here.
If it is broader endpoint monitoring, defensive agent behavior, or host telemetry correlation, it belongs elsewhere.
