```markdown
# AutoRuleGeneration

This directory contains the components used in our project to generate and experiment with YARA rules.

The structure is divided into two main parts:

```

AutoRuleGeneration/
│
├── Yaragen/
│
└── Yaralab/

```

## Yaragen

`Yaragen` contains the **original yarGen tool**, which is an open-source Python project used to automatically generate YARA rules from malware samples.

This folder includes the **core rule generation engine**, which:

- analyzes malware samples
- extracts distinctive strings and patterns
- filters out common strings using a goodware database
- generates candidate YARA detection rules

We keep this folder mostly unchanged so that the original tool remains intact and can be easily updated from the upstream GitHub repository if needed.

## Yaralab

`Yaralab` contains the **work done for this project**.

This includes:

- scripts for running yarGen on malware datasets
- experiments with rule generation
- generated YARA rules
- testing workflows
- integration with our malware scanning system

In short:

- **Yaragen** → the original rule generation engine  
- **Yaralab** → our project work built around that engine

## Summary

This structure separates:

- the **external tool (`yarGen`)**
- from **our custom experimentation and pipeline (`Yaralab`)**

This keeps the codebase organized and makes it easier to maintain or update the underlying tool without affecting our project work.
```
