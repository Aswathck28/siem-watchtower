import React, { useMemo } from 'react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';

/**
 * StarkRadar Component
 * Displays a hexagonal radar chart comparing Defense Coverage vs Active Threats.
 * 
 * @param {Array} intel - List of all MITRE techniques and their tactics/definitions.
 * @param {Array} coverage - List of techniques currently covered by defenses.
 * @param {Array} threats - List of active threats detected in the system.
 */
/**
 * Component: StarkRadar
 * Description: High-fidelity tactical radar chart comparing 'Defense Coverage' 
 *              (static MITRE baseline) against 'Active Threats' (real-time 
 *              anomalies). Visualizes 6 core kill-chain tactics using a 
 *              hexagonal HUD layout.
 * Parameters:
 *   - intel (Array): Full repository of MITRE techniques and definitions.
 *   - coverage (Array): List of techniques successfully covered by active rules.
 *   - threats (Array): Stream of currently detected security anomalies.
 * Returns:
 *   - JSX.Element
 */
const StarkRadar = ({ intel = [], coverage = [], threats = [] }) => {

    // The 6 main stages of the kill chain we are visualizing
    // Memoized to prevent recreation on every render
    const TACTICS = useMemo(() => [
        'Initial', 'Execution', 'Persist', 'PrivEsc', 'Defense', 'CredAccess'
    ], []);

    // Memoize the expensive data calculation to prevent re-renders
    const data = useMemo(() => {
        return TACTICS.map(tacticName => {
            const lowerTactic = tacticName.toLowerCase();

            // --- 1. DEFENSE SCORE (Green Layer) ---
            // Calculate how many techniques in this tactic are "covered" by our defenses.
            // Denominator: Total techniques in this tactic (from Intel feed)
            // Numerator: Covered techniques in this tactic

            const totalTechniques = intel.filter(i =>
                i.tactic && i.tactic.toLowerCase().includes(lowerTactic)
            ).length || 1; // Avoid division by zero

            const coveredTechniques = coverage.filter(c => {
                const match = intel.find(i => i.matrix_id === c.matrix_id);
                return match && match.tactic && match.tactic.toLowerCase().includes(lowerTactic);
            }).length;

            // Normalize score (Minimum 20% for visual presence)
            const coverageScore = Math.max(20, (coveredTechniques / totalTechniques) * 100);

            // --- 2. THREAT SCORE (Red Layer) ---
            // Check if ANY active threat matches this tactic.
            // If yes, spike the red layer to 100% to alert the user.

            const isThreatActive = threats.some(th => {
                if (!th.mapped_technique_id) return false;
                const techniqueInfo = intel.find(i => i.matrix_id === th.mapped_technique_id);
                return techniqueInfo && techniqueInfo.tactic && techniqueInfo.tactic.toLowerCase().includes(lowerTactic);
            });

            const threatScore = isThreatActive ? 100 : 0;

            return {
                tactic: tacticName.toUpperCase(),
                coverage: coverageScore,
                threat: threatScore,
                fullMark: 100
            };
        });
    }, [intel, coverage, threats, TACTICS]);

    // Custom Tick for proper text alignment on the polygon
    const CustomTick = ({ payload, x, y, cx, cy, ...rest }) => (
        <text
            {...rest}
            y={y + (y - cy) / 10}
            x={x + (x - cx) / 10}
            fontFamily="JetBrains Mono"
            fontSize={10}
            fill="#94a3b8"
            textAnchor="middle"
            style={{ filter: 'drop-shadow(0px 0px 2px rgba(14, 165, 233, 0.5))' }}
        >
            {payload.value}
        </text>
    );

    return (
        <div style={{ width: '100%', height: '100%', position: 'relative' }}>
            <ResponsiveContainer width="100%" height={260}>
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
                    <defs>
                        {/* Green Fade for Defense */}
                        <radialGradient id="gradCoverage" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
                            <stop offset="0%" stopColor="#10b981" stopOpacity={0.6} />
                            <stop offset="100%" stopColor="#10b981" stopOpacity={0.1} />
                        </radialGradient>

                        {/* Red Fade for Threats */}
                        <radialGradient id="gradThreat" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
                            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.8} />
                            <stop offset="100%" stopColor="#ef4444" stopOpacity={0.2} />
                        </radialGradient>

                        {/* Neon Glow Filter */}
                        <filter id="glow">
                            <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
                            <feMerge>
                                <feMergeNode in="coloredBlur" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                    </defs>

                    <PolarGrid gridType="polygon" stroke="rgba(34, 211, 238, 0.2)" strokeDasharray="4 4" />
                    <PolarAngleAxis dataKey="tactic" tick={<CustomTick />} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />

                    {/* LAYER 1: DEFENSE COVERAGE */}
                    <Radar
                        name="Defense Coverage"
                        dataKey="coverage"
                        stroke="#10b981"
                        strokeWidth={2}
                        fill="url(#gradCoverage)"
                        fillOpacity={1}
                        filter="url(#glow)"
                        isAnimationActive={true}
                    />

                    {/* LAYER 2: ACTIVE THREATS */}
                    <Radar
                        name="Active Threats"
                        dataKey="threat"
                        stroke="#ef4444"
                        strokeWidth={3}
                        fill="url(#gradThreat)"
                        fillOpacity={1}
                        filter="url(#glow)"
                        className={threats.length > 0 ? "pulse-radar" : ""}
                        isAnimationActive={true}
                    />
                </RadarChart>
            </ResponsiveContainer>

            {/* Center HUD Dot */}
            <div style={{
                position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
                width: '10px', height: '10px', background: '#22d3ee', borderRadius: '50%',
                boxShadow: '0 0 10px #22d3ee, 0 0 20px #22d3ee'
            }} />
        </div>
    );
};

export default StarkRadar;
