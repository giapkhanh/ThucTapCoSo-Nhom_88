import subprocess
import sys
import os
import time
import json

def compile_simulated_fixture():
    print("[*] Step 1: Compiling userspace concealment fixture (libhidepid.so)...")
    compile_cmd = ["gcc", "-shared", "-fPIC", "-o", "libhidepid.so", "libhidepid.c", "-ldl"]
    res = subprocess.run(compile_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Compilation failed:\n{res.stderr}", file=sys.stderr)
        sys.exit(1)
    print("    -> Compilation successful: ./libhidepid.so")

def run_evaluation():
    compile_simulated_fixture()
    
    so_path = os.path.abspath("./libhidepid.so")

    print("\n" + "=" * 65)
    print("       CONTROLLED PROCESS CONCEALMENT EVALUATION")
    print("=" * 65)

    # 1. Baseline Run (Clean environment)
    print("\n[*] Running Experiment 1: Clean Baseline System...")
    baseline_proc = subprocess.run(
        [sys.executable, "main.py", "--json"],
        capture_output=True,
        text=True
    )
    baseline_data = json.loads(baseline_proc.stdout)
    baseline_findings = baseline_data.get("findings", [])
    baseline_hidden = [f for f in baseline_findings if f["anomaly_type"] == "HIDDEN_FROM_PROCFS"]
    print(f"    -> Unexpected HIDDEN_FROM_PROCFS findings: {len(baseline_hidden)}")

    # 2. Concealment Experiment (Spawn target + LD_PRELOAD concealment)
    print("\n[*] Running Experiment 2: Controlled Concealment Simulation...")
    victim_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    target_pid = victim_proc.pid
    print(f"    -> Target Process Spawned: PID {target_pid}")
    
    time.sleep(0.5)

    try:
        env = os.environ.copy()
        env["LD_PRELOAD"] = so_path
        env["HIDE_PID"] = str(target_pid)

        attack_run = subprocess.run(
            [sys.executable, "main.py", "--json"],
            capture_output=True,
            text=True,
            env=env
        )

        attack_data = json.loads(attack_run.stdout)
        findings = attack_data.get("findings", [])
        
        hidden_findings = [f for f in findings if f["anomaly_type"] == "HIDDEN_FROM_PROCFS"]
        detected_pids = [f["pid"] for f in hidden_findings]
        
        target_detected = target_pid in detected_pids
        unexpected_hidden = [pid for pid in detected_pids if pid != target_pid]

        print(f"    -> Total Concealment Anomalies Detected: {len(hidden_findings)}")
        print(f"    -> Target PID {target_pid} Detected: {'YES' if target_detected else 'NO'}")

        # 3. Report Output
        print("\n" + "=" * 65)
        print("                 CONTROLLED EVALUATION REPORT")
        print("=" * 65)
        print(f" Evaluation Scope: Single-process controlled simulation (n=1)")
        print(f" Baseline unexpected findings:       {len(baseline_hidden)}")
        print(f" Target PID:                          {target_pid}")
        print(f" Target detected as HIDDEN_FROM_PROCFS: {'YES' if target_detected else 'NO'}")
        print(f" Unexpected HIDDEN_FROM_PROCFS:       {len(unexpected_hidden)}")
        print("-" * 65)
        
        if target_detected and len(unexpected_hidden) == 0 and len(baseline_hidden) == 0:
            print(" Result: PASS")
            print(" Summary: The detector successfully identified the single controlled")
            print("          concealment case with no unexpected HIDDEN_FROM_PROCFS findings.")
        else:
            print(" Result: FAIL")
        print("=" * 65)

    finally:
        victim_proc.terminate()
        victim_proc.wait()
        print("\n[*] Target process terminated.")

if __name__ == "__main__":
    run_evaluation()
