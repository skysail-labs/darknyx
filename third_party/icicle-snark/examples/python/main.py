import subprocess
import time
import os

NUMBER_OF_WARMUP = 2
NUMBER_OF_ITERATIONS = 5

BASE_PATH = os.path.abspath("../../benchmark/rsa/")

WITNESS = os.path.join(BASE_PATH, "witness.wtns")
ZKEY = os.path.join(BASE_PATH, "circuit_final.zkey")
PROOF = os.path.join(BASE_PATH, "proof.json")
PUBLIC = os.path.join(BASE_PATH, "public.json")
VERIFICATION_KEY = os.path.join(BASE_PATH, "verification_key.json")
DEVICE = "CPU"

PROCESS=None
DURATIONS = []

def create_process():
    """Create ICICLE SNARK process."""
    global PROCESS

    icicle_snark_path = os.environ.get("ICICLE_SNARK_PATH")

    if not icicle_snark_path:
        icicle_snark_path = "../.."
        print("Environment variable ICICLE_SNARK_PATH not set. Using default path")

    try:
        command = ["cargo", "run", "--release"]

        PROCESS = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=icicle_snark_path
        )

        print(f"Rust process started with PID: {PROCESS.pid}")
    except subprocess.CalledProcessError as e:
        print("create_process error:", e.stderr)
        return None

def run_command(command):
    try:
        start_time = time.time()
        PROCESS.stdin.write(command + "\n")
        PROCESS.stdin.flush()

        output = ""
        while "COMMAND_COMPLETED" not in output:
            output = PROCESS.stdout.readline().strip()
            print("output: ", output)

        elapsed_time = time.time() - start_time
        return elapsed_time

    except BrokenPipeError as e:
        logger.error(
            f"Error sending command {command} to Rust process: {e} for circuit {self.id} with pid {self.rust_process.pid}"
        )
        return None

def run_snarkjs():
    """Runs snarkjs g16v command."""
    try:
        command = ["snarkjs", "g16v", VERIFICATION_KEY, PUBLIC, PROOF]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
        print("snarkjs output:", result.stdout)
    except subprocess.CalledProcessError as e:
        print("snarkjs error:", e.stderr)

def main():
    create_process()
    command = f"prove --witness {WITNESS} --zkey {ZKEY} --proof {PROOF} --public {PUBLIC} --device {DEVICE}"
    elapsed_time = run_command(command)
    run_snarkjs()

if __name__ == "__main__":
    main()