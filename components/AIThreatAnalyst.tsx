'use client';

import { useEffect, useState, useRef } from 'react';
import {
  AlertCircle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  CircleCheck,
  Copy,
  HelpCircle,
  Languages,
  Loader2,
  MessageSquare,
  RefreshCw,
  Send,
  ShieldAlert,
  Sparkles,
  Terminal,
  XCircle,
  Zap,
} from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import { analyzeInvestigationWithAI, chatWithAIAnalyst, getAIStatus } from '@/lib/api';
import type {
  AIChatMessage,
  AIRecommendedAction,
  AIThreatAnalysis,
  Investigation,
  Severity,
} from '@/lib/types';

interface AIThreatAnalystProps {
  investigation: Investigation | null | undefined;
  className?: string;
}

const SUGGESTED_QUESTIONS = [
  'Why is this indicator considered risky?',
  'What should I do first?',
  'Could this result be a false positive?',
  'Which evidence supports this risk score?',
  'How can I reduce this security risk?',
  'Explain this report in simple Hindi.',
  'Explain this finding in technical English.',
];

export default function AIThreatAnalyst({
  investigation,
  className = '',
}: AIThreatAnalystProps) {
  const [language, setLanguage] = useState<'en' | 'hi'>('en');
  const [analysis, setAnalysis] = useState<AIThreatAnalysis | null>(null);
  const [isLoadingAnalysis, setIsLoadingAnalysis] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Status of the Gemini integration from backend
  const [aiBackendStatus, setAiBackendStatus] = useState<{
    gemini_configured: boolean;
    model: string;
    mode: string;
  } | null>(null);

  // Completed steps tracker
  const [completedActions, setCompletedActions] = useState<Record<string, boolean>>({});

  // Technical deep dive accordion
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  // Interactive chat state
  const [chatMessages, setChatMessages] = useState<AIChatMessage[]>([]);
  const [chatInput, setChatInput] = useState<string>('');
  const [isSendingMessage, setIsSendingMessage] = useState<boolean>(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const chatScrollRef = useRef<HTMLDivElement>(null);

  // 1. Fetch AI backend status once on mount
  useEffect(() => {
    getAIStatus().then((res) => {
      if (res) {
        setAiBackendStatus({
          gemini_configured: res.gemini_configured,
          model: res.model,
          mode: res.mode,
        });
      }
    });
  }, []);

  // 2. Fetch or load analysis whenever selected investigation or language changes
  useEffect(() => {
    if (!investigation) return;

    let isMounted = true;

    // Reset chat history when investigation switches to avoid cross-investigation contamination
    setChatMessages([
      {
        role: 'assistant',
        content:
          language === 'hi'
            ? `नमस्ते! मैं ThreatNova AI का थ्रेट विश्लेषक हूँ। मैं लक्ष्य '${investigation.query}' (${investigation.type.toUpperCase()}) के विश्लेषण के लिए तैयार हूँ। आप नीचे दिए गए सुझावों में से प्रश्न चुन सकते हैं या अपना प्रश्न पूछ सकते हैं।`
            : `Hello! I am ThreatNova AI's Lead Threat Intelligence Analyst. I have loaded empirical evidence for target '${investigation.query}' (${investigation.type.toUpperCase()}). You can ask me about contributing factors, defensive priorities, or false-positive verification.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
    setChatError(null);

    // Check if investigation object already embeds cached AI analysis for this language
    if (investigation.aiAnalysis && investigation.aiAnalysis[language]) {
      setAnalysis(investigation.aiAnalysis[language]);
      setIsLoadingAnalysis(false);
      setAnalysisError(null);
      return;
    }

    async function loadAnalysis() {
      setIsLoadingAnalysis(true);
      setAnalysisError(null);

      try {
        const res = await analyzeInvestigationWithAI(
          investigation!.id,
          language,
          // Pass full investigation payload so demo / in-memory items work seamlessly
          investigation
        );
        if (isMounted) {
          setAnalysis(res);
          setIsLoadingAnalysis(false);
        }
      } catch (err: any) {
        if (isMounted) {
          console.warn('Failed to load AI Threat Analysis:', err);
          setAnalysisError(
            err.message || 'Unable to generate AI threat analysis. Please retry.'
          );
          setIsLoadingAnalysis(false);
        }
      }
    }

    loadAnalysis();

    return () => {
      isMounted = false;
    };
  }, [investigation?.id, language]);

  // Scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages, isSendingMessage]);

  const handleToggleActionCompletion = (title: string) => {
    setCompletedActions((prev) => ({
      ...prev,
      [title]: !prev[title],
    }));
  };

  const handleSendChatMessage = async (msgToSend?: string) => {
    const text = (msgToSend !== undefined ? msgToSend : chatInput).trim();
    if (!text || isSendingMessage || !investigation) return;

    setChatInput('');
    setChatError(null);

    const userMsg: AIChatMessage = {
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const newHistory = [...chatMessages, userMsg];
    setChatMessages(newHistory);
    setIsSendingMessage(true);

    try {
      const res = await chatWithAIAnalyst(
        investigation.id,
        text,
        language,
        chatMessages,
        investigation
      );

      const assistantMsg: AIChatMessage = {
        role: 'assistant',
        content: res.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setChatMessages((prev) => [...prev, assistantMsg]);
      setIsSendingMessage(false);
    } catch (err: any) {
      setChatError(err.message || 'Failed to receive response from AI Analyst.');
      setIsSendingMessage(false);
    }
  };

  const handleAskAboutStep = (action: AIRecommendedAction) => {
    const query =
      language === 'hi'
        ? `कृपया इस सुरक्षा उपाय के बारे में विस्तार से बताएं: "${action.title}". इसका मुख्य कारण क्या है और इसे सुरक्षित रूप से कैसे लागू किया जाए?`
        : `Please give me detailed guidance for this recommended step: "${action.title}". What is the priority reason and what are the exact safe implementation steps?`;
    handleSendChatMessage(query);
  };

  const handleCopyMessage = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (!investigation) {
    return (
      <section className={`rounded-xl border border-tn-border bg-tn-surface p-6 ${className}`}>
        <div className="flex items-center gap-3 text-tn-muted">
          <Bot size={20} className="text-tn-info" />
          <p className="text-sm">Select an investigation to launch the AI Threat Analyst.</p>
        </div>
      </section>
    );
  }

  const isGeminiLive = analysis?.is_ai_generated ?? aiBackendStatus?.gemini_configured ?? false;
  const activeModel = analysis?.model_used || aiBackendStatus?.model || 'Google Gemini (gemini-2.5-flash)';

  return (
    <section
      aria-labelledby="ai-threat-analyst-title"
      className={`rounded-2xl border border-tn-border bg-tn-surface shadow-xl overflow-hidden ${className}`}
    >
      {/* ── Top Header Bar ── */}
      <div className="flex flex-col gap-3 border-b border-tn-border bg-tn-card/50 p-4 sm:p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-tn-border bg-tn-bg shadow-sm">
            <Bot size={22} className="text-tn-info" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 id="ai-threat-analyst-title" className="text-base font-bold text-tn-text">
                AI Threat Analyst
              </h3>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-mono font-medium border ${
                  isGeminiLive
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                    : 'border-tn-border bg-tn-card text-tn-muted'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    isGeminiLive ? 'bg-emerald-400 animate-pulse' : 'bg-tn-muted'
                  }`}
                />
                {isGeminiLive ? 'Google Gemini Live' : 'Autonomous Engine'}
              </span>
            </div>
            <p className="text-xs text-tn-muted font-mono mt-0.5">
              Active Context: <span className="text-tn-text font-bold">{investigation.query}</span> ({investigation.type.toUpperCase()}) · {investigation.id}
            </p>
          </div>
        </div>

        {/* Right side controls: Language toggle and refresh */}
        <div className="flex items-center gap-2.5 self-end sm:self-auto">
          {/* Language Switcher */}
          <div className="inline-flex rounded-lg border border-tn-border bg-tn-bg p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setLanguage('en')}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                language === 'en'
                  ? 'bg-tn-card text-tn-text font-semibold shadow-sm'
                  : 'text-tn-muted hover:text-tn-text'
              }`}
            >
              English
            </button>
            <button
              type="button"
              onClick={() => setLanguage('hi')}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors flex items-center gap-1 ${
                language === 'hi'
                  ? 'bg-tn-card text-tn-text font-semibold shadow-sm'
                  : 'text-tn-muted hover:text-tn-text'
              }`}
            >
              <Languages size={12} />
              हिंदी
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              setIsLoadingAnalysis(true);
              analyzeInvestigationWithAI(investigation.id, language, investigation)
                .then((res) => {
                  setAnalysis(res);
                  setIsLoadingAnalysis(false);
                })
                .catch(() => setIsLoadingAnalysis(false));
            }}
            disabled={isLoadingAnalysis}
            title="Refresh Threat Analysis"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-tn-border bg-tn-card text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors disabled:opacity-50"
          >
            <RefreshCw size={13} className={isLoadingAnalysis ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <div className="p-4 sm:p-6 space-y-6">
        {/* Loading State */}
        {isLoadingAnalysis && !analysis && (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Loader2 size={32} className="animate-spin text-tn-info" />
            <p className="mt-3 text-sm font-medium text-tn-text">
              Synthesizing threat intelligence with Gemini AI…
            </p>
            <p className="text-xs text-tn-muted font-mono mt-1">
              Analyzing reputation signals, DNS records, and empirical findings for {investigation.query}
            </p>
          </div>
        )}

        {/* Error State */}
        {analysisError && !analysis && (
          <div className="rounded-xl border border-tn-danger/40 bg-tn-danger/10 p-4 text-xs">
            <div className="flex items-center gap-2 text-tn-danger font-semibold">
              <AlertCircle size={15} />
              <span>AI Analysis Unavailable</span>
            </div>
            <p className="mt-1 text-tn-muted">{analysisError}</p>
            <button
              type="button"
              onClick={() => {
                setIsLoadingAnalysis(true);
                analyzeInvestigationWithAI(investigation.id, language, investigation)
                  .then(setAnalysis)
                  .finally(() => setIsLoadingAnalysis(false));
              }}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-3 py-1.5 text-xs text-tn-text hover:border-tn-muted"
            >
              <RefreshCw size={12} /> Retry Analysis
            </button>
          </div>
        )}

        {/* ── Content View ── */}
        {analysis && (
          <>
            {/* Section A: Executive Summary Banner */}
            <div className="rounded-xl border border-tn-border/80 bg-tn-card/40 p-4 sm:p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-tn-border/60 pb-3">
                <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-tn-info flex items-center gap-1.5">
                  <Sparkles size={13} className="text-tn-warn" />
                  Executive Security Brief
                </span>
                <span className="text-[10px] font-mono text-tn-muted">
                  Model: {activeModel}
                </span>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-tn-text font-sans font-medium">
                {analysis.executive_summary}
              </p>
            </div>

            {/* Section B: Risk Classification & Engine Alignment */}
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="rounded-xl border border-tn-border bg-tn-card/60 p-4">
                <span className="text-[10px] font-mono uppercase text-tn-muted block">Risk Level</span>
                <div className="mt-2 flex items-center gap-2">
                  <SeverityBadge severity={investigation.risk.level as Severity} />
                  <span className="font-mono text-xs font-bold text-tn-text">
                    {investigation.risk.score}/100
                  </span>
                </div>
                <p className="mt-2 text-[11px] text-tn-muted">
                  Confidence: <span className="font-mono text-tn-info font-medium">{analysis.confidence}</span>
                </p>
              </div>

              <div className="sm:col-span-2 rounded-xl border border-tn-border bg-tn-card/60 p-4">
                <span className="text-[10px] font-mono uppercase text-tn-muted block">
                  Classification Rationale
                </span>
                <p className="mt-1.5 text-xs leading-relaxed text-tn-text font-sans">
                  {analysis.risk_classification_explanation}
                </p>
              </div>
            </div>

            {/* Section C: Threat Explanation (Key Findings) */}
            {analysis.key_findings && analysis.key_findings.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-tn-text flex items-center gap-2">
                    <ShieldAlert size={14} className="text-tn-warn" />
                    Threat Explanation &amp; Key Findings ({analysis.key_findings.length})
                  </h4>
                  <span className="text-[10px] font-mono text-tn-muted">Evidence Grounded</span>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  {analysis.key_findings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-tn-border/80 bg-tn-card/50 p-4 flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2">
                          <h5 className="text-xs font-bold text-tn-text font-mono">
                            {finding.title}
                          </h5>
                          <span className="text-[9px] font-mono px-2 py-0.5 rounded border border-tn-border bg-tn-bg text-tn-info">
                            {finding.confidence} Confidence
                          </span>
                        </div>
                        <p className="mt-2 text-xs leading-relaxed text-tn-muted">
                          {finding.explanation}
                        </p>
                      </div>

                      {finding.evidence && finding.evidence.length > 0 && (
                        <div className="mt-3 pt-2.5 border-t border-tn-border/60">
                          <span className="text-[10px] font-mono uppercase text-tn-muted block mb-1">
                            Supporting Telemetry:
                          </span>
                          <div className="space-y-1">
                            {finding.evidence.map((ev, eIdx) => (
                              <div
                                key={eIdx}
                                className="font-mono text-[10px] rounded bg-tn-bg/80 border border-tn-border/40 px-2 py-0.5 text-tn-text truncate"
                                title={ev}
                              >
                                {ev}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Section D & 5: Interactive Risk Guidance - Recommended Next Steps */}
            {analysis.recommended_actions && analysis.recommended_actions.length > 0 && (
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                  <div>
                    <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-tn-text flex items-center gap-2">
                      <Zap size={14} className="text-tn-warn" />
                      Recommended Next Steps
                    </h4>
                    <p className="text-[11px] text-tn-muted mt-0.5">
                      Prioritized defensive actions. ThreatNova advises; the analyst executes.
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-tn-muted">
                    {Object.values(completedActions).filter(Boolean).length} / {analysis.recommended_actions.length} Completed
                  </span>
                </div>

                <div className="space-y-2.5">
                  {analysis.recommended_actions.map((act, idx) => {
                    const isDone = Boolean(completedActions[act.title]);
                    const priorityColor =
                      act.priority.toLowerCase().includes('immediate') || act.priority.toLowerCase().includes('high')
                        ? 'border-tn-danger/40 bg-tn-danger/10 text-tn-danger'
                        : act.priority.toLowerCase().includes('short') || act.priority.toLowerCase().includes('medium')
                        ? 'border-tn-warn/40 bg-tn-warn/10 text-tn-warn'
                        : 'border-tn-info/40 bg-tn-info/10 text-tn-info';

                    return (
                      <div
                        key={idx}
                        className={`rounded-xl border p-4 transition-all ${
                          isDone
                            ? 'border-emerald-500/30 bg-emerald-950/10 opacity-75'
                            : 'border-tn-border bg-tn-card/40'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-3">
                            <button
                              type="button"
                              onClick={() => handleToggleActionCompletion(act.title)}
                              className="mt-0.5 text-tn-muted hover:text-emerald-400 transition-colors cursor-pointer"
                              aria-label={`Mark action '${act.title}' as complete`}
                            >
                              {isDone ? (
                                <CircleCheck size={18} className="text-emerald-400" />
                              ) : (
                                <div className="h-4.5 w-4.5 rounded-full border border-tn-border hover:border-tn-text" />
                              )}
                            </button>
                            <div>
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${priorityColor}`}>
                                  {act.priority}
                                </span>
                                <h5 className={`text-xs font-bold font-mono ${isDone ? 'line-through text-tn-muted' : 'text-tn-text'}`}>
                                  {act.title}
                                </h5>
                              </div>
                              <p className="mt-1.5 text-xs text-tn-muted leading-relaxed">
                                <strong className="text-tn-text font-medium">Why it matters:</strong> {act.reason}
                              </p>
                              {act.expected_benefit && (
                                <p className="mt-1 text-[11px] text-tn-info">
                                  <strong className="text-tn-muted font-normal">Expected benefit:</strong> {act.expected_benefit}
                                </p>
                              )}
                            </div>
                          </div>

                          {/* Ask AI about this action */}
                          <button
                            type="button"
                            onClick={() => handleAskAboutStep(act)}
                            className="shrink-0 text-[10px] font-mono text-tn-info hover:text-tn-text rounded border border-tn-border px-2.5 py-1 bg-tn-bg hover:border-tn-muted transition-colors flex items-center gap-1"
                          >
                            <MessageSquare size={10} />
                            Ask AI
                          </button>
                        </div>

                        {/* Steps */}
                        {act.steps && act.steps.length > 0 && (
                          <div className="mt-3 ml-7 pt-2.5 border-t border-tn-border/40">
                            <span className="text-[10px] font-mono uppercase text-tn-muted block mb-1">
                              Step-by-step guidance:
                            </span>
                            <ol className="list-decimal list-inside space-y-1 text-xs text-tn-muted">
                              {act.steps.map((st, sIdx) => (
                                <li key={sIdx} className="leading-relaxed">
                                  <span className="text-tn-text font-sans">{st}</span>
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Section E: What to Do and What to Avoid */}
            <div className="grid gap-4 sm:grid-cols-2">
              {/* What To Do */}
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/10 p-4">
                <h5 className="text-xs font-mono font-bold uppercase text-emerald-400 flex items-center gap-1.5 mb-2.5">
                  <CheckCircle2 size={14} />
                  Safe Practices (What To Do)
                </h5>
                <ul className="space-y-1.5 text-xs text-tn-muted">
                  {analysis.safe_practices.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-emerald-400 shrink-0 font-bold">✓</span>
                      <span className="leading-relaxed text-tn-text">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* What To Avoid */}
              <div className="rounded-xl border border-tn-danger/40 bg-tn-danger/10 p-4">
                <h5 className="text-xs font-mono font-bold uppercase text-tn-danger flex items-center gap-1.5 mb-2.5">
                  <XCircle size={14} />
                  Actions to Avoid (Risky Behaviors)
                </h5>
                <ul className="space-y-1.5 text-xs text-tn-muted">
                  {analysis.actions_to_avoid.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-tn-danger shrink-0 font-bold">✕</span>
                      <span className="leading-relaxed text-tn-text">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Section F: False Positive & Uncertainty Analysis */}
            <div className="rounded-xl border border-tn-border bg-tn-card/50 p-4">
              <div className="flex items-center gap-2 text-xs font-mono font-semibold uppercase tracking-wider text-tn-text mb-2">
                <HelpCircle size={14} className="text-tn-info" />
                False Positive &amp; Uncertainty Analysis
              </div>
              <p className="text-xs leading-relaxed text-tn-muted font-sans">
                {analysis.false_positive_analysis}
              </p>
            </div>

            {/* Section G: Expandable Technical Explanation */}
            <div className="rounded-xl border border-tn-border bg-tn-bg">
              <button
                type="button"
                onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                className="w-full flex items-center justify-between p-4 text-xs font-mono font-semibold text-tn-text hover:bg-tn-card/40 transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Terminal size={14} className="text-tn-info" />
                  Advanced Technical Deep Dive (For Engineers &amp; Students)
                </span>
                {showTechnicalDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>
              {showTechnicalDetails && (
                <div className="p-4 border-t border-tn-border text-xs leading-relaxed text-tn-muted space-y-3 font-mono bg-black/30">
                  <p>{analysis.technical_explanation}</p>
                  {analysis.limitations && analysis.limitations.length > 0 && (
                    <div className="pt-2 border-t border-tn-border/50">
                      <span className="text-[10px] text-tn-muted uppercase block mb-1">
                        Operational Limitations:
                      </span>
                      <ul className="list-disc list-inside space-y-0.5 text-[11px] text-tn-muted">
                        {analysis.limitations.map((lim, lIdx) => (
                          <li key={lIdx}>{lim}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* ── Section 4: Interactive AI Assistant Chat ── */}
            <div className="rounded-xl border border-tn-border bg-tn-card/40 overflow-hidden">
              <div className="border-b border-tn-border bg-tn-card/70 px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <MessageSquare size={14} className="text-tn-info" />
                  <span className="text-xs font-bold font-mono text-tn-text">
                    Ask Gemini AI Threat Analyst
                  </span>
                </div>
                <span className="text-[10px] font-mono text-tn-muted">
                  Context: {investigation.query}
                </span>
              </div>

              {/* Suggested Questions Chips */}
              <div className="p-3 border-b border-tn-border/60 bg-tn-bg/50">
                <span className="text-[10px] font-mono text-tn-muted block mb-1.5 uppercase">
                  Suggested Questions:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {SUGGESTED_QUESTIONS.map((qText) => (
                    <button
                      key={qText}
                      type="button"
                      onClick={() => handleSendChatMessage(qText)}
                      disabled={isSendingMessage}
                      className="text-[10px] font-mono rounded-md border border-tn-border bg-tn-card px-2.5 py-1 text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors text-left disabled:opacity-50"
                    >
                      {qText}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chat Message Stream */}
              <div
                ref={chatScrollRef}
                className="p-4 space-y-3 max-h-72 overflow-y-auto font-sans text-xs"
              >
                {chatMessages.map((msg, idx) => {
                  const isUser = msg.role === 'user';
                  return (
                    <div
                      key={idx}
                      className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
                    >
                      <div
                        className={`max-w-[85%] rounded-xl p-3 relative group ${
                          isUser
                            ? 'bg-tn-info/15 text-tn-text border border-tn-info/30'
                            : 'bg-tn-surface text-tn-text border border-tn-border'
                        }`}
                      >
                        {!isUser && (
                          <div className="flex items-center justify-between gap-4 mb-1 pb-1 border-b border-tn-border/40 text-[10px] font-mono text-tn-muted">
                            <span className="flex items-center gap-1 text-tn-info font-bold">
                              <Bot size={11} /> Gemini Threat Analyst
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopyMessage(msg.content, idx)}
                              className="text-tn-muted hover:text-tn-text transition-colors"
                              title="Copy response"
                            >
                              {copiedIndex === idx ? (
                                <CheckCircle2 size={11} className="text-emerald-400" />
                              ) : (
                                <Copy size={11} />
                              )}
                            </button>
                          </div>
                        )}
                        <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                        {msg.timestamp && (
                          <span className="block text-[9px] font-mono text-tn-muted/70 text-right mt-1">
                            {msg.timestamp}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}

                {isSendingMessage && (
                  <div className="flex items-center gap-2 text-tn-muted font-mono text-[11px] py-1">
                    <Loader2 size={13} className="animate-spin text-tn-info" />
                    <span>Gemini AI is analyzing evidence…</span>
                  </div>
                )}
              </div>

                {chatError && (
                <div className="p-2.5 mx-3 mb-2 rounded bg-tn-danger/10 border border-tn-danger/30 text-[11px] text-tn-danger flex items-center justify-between">
                  <span>{chatError}</span>
                  <button
                    type="button"
                    onClick={() => setChatError(null)}
                    className="underline hover:text-white"
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Chat Input Field */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendChatMessage();
                }}
                className="p-3 border-t border-tn-border bg-tn-surface flex items-center gap-2"
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder={
                    language === 'hi'
                      ? 'इस इंडिकेटर के बारे में कोई भी प्रश्न पूछें (उदा. क्या यह सुरक्षित है?)...'
                      : 'Ask Gemini any follow-up question about this threat report…'
                  }
                  disabled={isSendingMessage}
                  className="flex-1 rounded-lg border border-tn-border bg-tn-card px-3 py-2 text-xs text-tn-text placeholder:text-tn-muted/60 focus:border-tn-muted focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!chatInput.trim() || isSendingMessage}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-tn-info/20 border border-tn-info/40 px-3 py-2 text-xs font-semibold text-tn-text hover:bg-tn-info/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Send size={13} />
                  <span className="hidden sm:inline">Send</span>
                </button>
              </form>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
