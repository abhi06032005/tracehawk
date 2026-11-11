"use client";

import React, { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { CopilotWorkspace } from "@/components/copilot/CopilotWorkspace";
import { NewMissionModal } from "@/components/copilot/NewMissionModal";

export default function CopilotPage() {
  const [missions, setMissions] = useState<any[]>([]);
  const [selectedMission, setSelectedMission] = useState<any>(null);
  const [investigation, setInvestigation] = useState<any>(null);
  const [checklistData, setChecklistData] = useState<any>(null);
  const [graphData, setGraphData] = useState<any>(null);
  const [config, setConfig] = useState<any>(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Load config & recent missions on mount
  const loadInitialData = async () => {
    try {
      const [cfg, missRes] = await Promise.all([
        api.getAiConfig().catch(() => null),
        api.getCopilotMissions().catch(() => ({ missions: [] })),
      ]);

      setConfig(cfg);
      const missionList = missRes.missions || [];
      setMissions(missionList);

      if (missionList.length > 0 && !selectedMission) {
        setSelectedMission(missionList[0]);
        if (missionList[0].investigationId) {
          await loadInvestigationData(missionList[0].investigationId);
        }
      }
    } catch (err: any) {
      setError(err.message || "Failed to load initial copilot state");
    }
  };

  const loadInvestigationData = async (invId: string) => {
    try {
      const [invRes, chkRes, grpRes] = await Promise.all([
        api.getInvestigation(invId).catch(() => ({ investigation: null })),
        api.getCopilotChecklist(invId).catch(() => null),
        api.getCopilotGraph(invId).catch(() => null),
      ]);

      if (invRes.investigation) {
        setInvestigation(invRes.investigation);
      }
      if (chkRes) {
        setChecklistData(chkRes);
      }
      if (grpRes) {
        setGraphData(grpRes);
      }
    } catch (err: any) {
      console.error("Error refreshing investigation data:", err);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // Poll active investigation while running
  useEffect(() => {
    const isRunning = investigation?.status === "RUNNING" || investigation?.status === "AWAITING_APPROVAL";
    if (!investigation?.id || !isRunning) return;

    const timer = setInterval(() => {
      loadInvestigationData(investigation.id);
    }, 2500);

    return () => clearInterval(timer);
  }, [investigation?.id, investigation?.status]);

  const handleLaunchMission = async (data: {
    targetUrl: string;
    name?: string;
    mode: "autonomous" | "quick" | "api" | "recon";
    activeTests: boolean;
    maxSteps: number;
  }) => {
    setBusy(true);
    setError("");
    try {
      const launchRes = await api.launchCopilotMission(data);
      // Refresh missions and poll for new investigation
      setTimeout(async () => {
        const missRes = await api.getCopilotMissions();
        setMissions(missRes.missions);
        const newlyCreated = missRes.missions.find((m) => m.sessionId === launchRes.sessionId);
        if (newlyCreated) {
          setSelectedMission(newlyCreated);
          if (newlyCreated.investigationId) {
            await loadInvestigationData(newlyCreated.investigationId);
          }
        }
        setBusy(false);
      }, 2000);
    } catch (err: any) {
      setBusy(false);
      throw err;
    }
  };

  const handleStopMission = async () => {
    if (!investigation?.id) return;
    try {
      await api.stopInvestigation(investigation.id);
      await loadInvestigationData(investigation.id);
    } catch (err: any) {
      setError(err.message || "Failed to stop investigation");
    }
  };

  return (
    <div className="relative h-screen w-full overflow-hidden bg-slate-950">
      <CopilotWorkspace
        mission={selectedMission}
        investigation={investigation}
        checklistData={checklistData}
        graphData={graphData}
        config={config}
        onRefresh={async () => {
          if (investigation?.id) await loadInvestigationData(investigation.id);
        }}
        onStop={handleStopMission}
        onNewMissionClick={() => setIsModalOpen(true)}
        busy={busy}
      />

      <NewMissionModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onLaunch={handleLaunchMission}
        busy={busy}
      />
    </div>
  );
}

