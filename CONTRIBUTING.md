# Contributing to ThreatLens

Thank you for contributing to ThreatLens! We welcome improvements to scoring algorithms, telemetry connectors, and SOC workflows.

## Development Workflow

1. **Clone & Setup:**
   ```bash
   git clone https://github.com/organization/threatlens.git
   cd threatlens
   npm install
   ```

2. **Generate Synthetic Datasets:**
   ```bash
   python3 scripts/generate_dataset.py
   ```

3. **Run Automated Tests:**
   ```bash
   python3 -m unittest discover tests
   ```

4. **Run Benchmark Experiments:**
   ```bash
   python3 experiments/run_experiment.py
   ```

5. **Start Development Server:**
   ```bash
   npm run dev
   ```

## Pull Request Guidelines

- Ensure all 17 unit, edge case, and security tests pass.
- Maintain transparent mathematical scoring (no unexplainable black-box logic).
- Preserve role-based access control and audit trail logging for all new endpoints.
