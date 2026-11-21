# Third-party material

`evals/build_dataset.py` composes `dataset_v2.jsonl` partly from these MIT-licensed sources.
Fetch them with `evals/fetch_external.sh`. Each folder keeps the upstream license file.

| Source | Used for | License |
|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zürich SPY Lab) | Attack templates `direct`, `ignore_previous`, `system_message`, `injecagent`, `important_instructions` | MIT |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (UIUC Kang Lab) | Six tool-output carriers (Amazon, GitHub, Gmail, Calendar, Shopify, Todoist) | MIT |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) (Microsoft) | 24 human-written attack emails that triggered the email tool in the original challenge, plus benign emails from scenario 2 | MIT |

Citations: Debenedetti et al., *AgentDojo* (NeurIPS 2024 D&B); Zhan et al., *InjecAgent* (Findings of ACL 2024);
Abdelnabi et al., *LLMail-Inject* (2025).
