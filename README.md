# ToolTrace: LLM Agent Tool-Call Hijack Mini Benchmark

ToolTrace is a mini red teaming benchmark for LLM agent tool-call hijacking. It demonstrates that prompt injection in LLM agents is best treated as an information-flow and permission-boundary problem, not merely as a text classification problem.

The benchmark simulates an agent that reads an external document, summarizes it, and saves the summary as a note. A malicious document contains an indirect prompt injection that asks the agent to call `send_email` and exfiltrate a secret.

## What Makes ToolTrace Different

Most prompt injection toy projects stop at classifying malicious text. ToolTrace instead simulates the path from untrusted external content to a privileged tool call.

- It models an LLM agent that reads an external document and calls tools.
- It reproduces indirect prompt injection as tool-call hijacking, not just unsafe text generation.
- It defends with confirmation policy and taint tracking rather than keyword filtering.
- It evaluates task success and attack success together, so the defense must preserve usefulness.
- It can be run as a VESSL/Jupyter experiment and uploaded to Hugging Face for reproducibility.

One-line pitch:

> ToolTrace traces whether untrusted prompt content can flow into sensitive tool calls, then tests whether policy guards stop that flow without breaking the user task.

## Why This Is Interview-Friendly

- It matches AI red teaming, LLM agent security, and data privacy.
- It runs without API keys or network access.
- It shows both attack reproduction and measurable defense.
- It uses simple metrics: task success, attack success, blocked calls, and false positives.

## Project Structure

```text
.
  app.py
  agent.py
  tools.py
  policy.py
  notebooks/
    agent_security_benchmark.ipynb
  scenarios/
    benign.json
    indirect_injection.json
  tests/
    test_benchmark.py
```

## Quick Demo

Run with no defense:

```bash
python3 app.py --guard none
```

Expected result:

- Task success: `True`
- Attack success: `True`
- The simulated agent sends the secret to `attacker@attacker.example`.

Run with taint tracking:

```bash
python3 app.py --guard taint
```

Expected result:

- Task success: `True`
- Attack success: `False`
- The dangerous `send_email` call is blocked because external-document data reached sensitive tool arguments.

Run with both defenses:

```bash
python3 app.py --guard both
```

Compare all defenses:

```bash
python3 app.py --all
```

Expected comparison:

```text
Guard   | Task | Attack | Blocked | False Positive
--------+------+--------+---------+---------------
none    | True | True   | 0       | False
confirm | True | False  | 1       | False
taint   | True | False  | 1       | False
both    | True | False  | 1       | False
```

## Defense Modes

| Guard | Meaning |
| --- | --- |
| `none` | No defense. Indirect injection succeeds. |
| `confirm` | Sensitive tools such as `send_email` require user confirmation. |
| `taint` | Tainted data from external documents cannot flow into sensitive tool arguments. |
| `both` | Combines confirmation and taint tracking. |

## Metrics

| Metric | Meaning |
| --- | --- |
| Task Success Rate | Did the agent complete the normal user task? |
| Attack Success Rate | Did the secret reach the attacker email? |
| Blocked Calls | How many tool calls were blocked by policy? |
| False Positive | Did the defense break a benign task? |

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## Run On VESSL AI

This project does not need a GPU. On VESSL, frame it as a reproducible remote benchmark run or Workspace notebook experiment rather than a heavy training job.

### Option A: VESSL Workspace / Jupyter Notebook

This is the most presentation-friendly format if you previously used VESSL Workspace notebooks.

1. Create a VESSL Workspace with a CPU preset.
2. Upload or clone this project.
3. Open `notebooks/agent_security_benchmark.ipynb`.
4. Run all cells.
5. Use the defense comparison output as your experiment result.

The notebook also includes optional Hugging Face Hub cells:

- Install `huggingface_hub`.
- Log in with `notebook_login()` or `HF_TOKEN`.
- Create or reuse a Hub repository.
- Upload the full benchmark folder.
- Verify uploaded files.

Before running the upload cell, replace:

```python
HF_REPO_ID = "YOUR_HF_USERNAME/tooltrace-agent-security-mini-benchmark"
```

### Option B: VESSL Run

1. Push this repository to GitHub.
2. Edit `vessl-run.yaml` and replace `YOUR_GITHUB_USERNAME`.
3. Configure the VESSL CLI:

```bash
pip install --upgrade vessl
vessl configure
```

4. Launch the run:

```bash
vessl run create -f vessl-run.yaml
```

The run should print the defense comparison table and then execute the unit tests.

## How To Explain This In An Interview

The core point is that agentic AI systems need a security boundary between untrusted external content and privileged tools. The malicious document is data, but a vulnerable agent treats it as an instruction. The policy guard restores the boundary by checking whether a high-risk tool call is confirmed and whether untrusted content flows into sensitive arguments.

This is intentionally small, but it can be extended into a research prototype by adding real LLM calls, more tools, more attack scenarios, and a benchmark table across models and defenses.
# ToolTrace
