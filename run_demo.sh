#!/usr/bin/env bash
# ==============================================================================
# Post-Quantum Secure IoT Communication Demo Launcher
# Launches the Python PQC Gateway Server and the LiteX RISC-V Verilator Node
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="/home/asus/pqc/Constraint_Env_Sim/build/sim/gateware"

NUM_PACKETS=${1:-5}

echo "=================================================================="
echo " Starting Post-Quantum Secure IoT Communication MVP Demo"
echo " Target Packets: ${NUM_PACKETS}"
echo "=================================================================="

# Ensure previous instances are cleaned up
pkill -f "server.py" > /dev/null 2>&1 || true
pkill -f "Vsim" > /dev/null 2>&1 || true

# 1. Start Gateway Server in background
echo "[DEMO] Launching PQC Gateway Server..."
python3 -u "${PROJECT_ROOT}/server/server.py" "${NUM_PACKETS}" &
SERVER_PID=$!

# Give server time to bind socket
sleep 0.5

# 2. Launch Bare-Metal LiteX/VexRiscv Node Simulation
echo "[DEMO] Launching RISC-V Emulation (LiteX + Verilator)..."
cd "${SIM_DIR}"
timeout 30 ./run_sim.sh < /dev/null &
SIM_PID=$!

# 3. Wait for Server to finish recording target packets
wait "${SERVER_PID}" || true

# 4. Clean up simulation process
kill -9 "${SIM_PID}" > /dev/null 2>&1 || true
wait "${SIM_PID}" 2>/dev/null || true

echo ""
echo "=================================================================="
echo " Demo Complete! Analyzing Recorded PCAP Session..."
echo "=================================================================="
python3 "${PROJECT_ROOT}/server/analyze_pcap.py" "${PROJECT_ROOT}/pqc_session.pcap"
