// app/page.tsx
"use client";

import { motion } from "framer-motion";
import {
  Phone,
  Mail,
  Shield,
  MapPin,
  Users,
  Bell,
  FileText,
  BarChart3,
  Menu,
  X,
  AlertTriangle,
  Users2,
  Building2,
  Ambulance,
  ClipboardCheck,
  ArrowRight,
  ChevronDown,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import {
  RevealOnScroll,
  RevealOnScrollButton,
} from "@/components/RevealOnScroll";

const SECTION_IDS = [
  "why-choose",
  "how-it-works",
  "national-disaster",
] as const;
type SectionId = (typeof SECTION_IDS)[number];

function isSectionId(id: string): id is SectionId {
  return (SECTION_IDS as readonly string[]).includes(id);
}

function Container({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-w-screen-2xl mx-auto px-6 md:px-8 2xl:px-10">
      {children}
    </div>
  );
}

export default function Home() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  /** Set when a section nav link is clicked; scroll position does not change it. */
  const [selectedSection, setSelectedSection] = useState<SectionId | null>(
    null,
  );
  const [lang, setLang] = useState<"en" | "bn">("en");

  const scrollToSection = (id: string) => {
    setIsMobileMenuOpen(false);
    if (isSectionId(id)) {
      setSelectedSection(id);
    }
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  const desktopSectionNavClass = (id: SectionId) =>
    [
      "cursor-pointer rounded-lg px-4 py-2.5 transition-colors text-xl",
      selectedSection === id
        ? "text-[#002D62] font-medium hover:text-[#002D62]"
        : "text-gray-700 font-medium hover:text-[#006747]",
    ].join(" ");

  const mobileSectionNavClass = (id: SectionId) =>
    [
      "cursor-pointer rounded-lg px-4 py-2.5 transition-colors text-lg font-medium",
      selectedSection === id
        ? "text-[#002D62] hover:text-[#002D62]"
        : "text-gray-700 hover:text-[#006747]",
    ].join(" ");

  const langToggleClass = (code: "en" | "bn") =>
    [
      "cursor-pointer rounded-full px-6 py-2.5 text-base font-medium transition-colors",
      lang === code
        ? "bg-[#002D62] text-white"
        : "text-gray-700 hover:bg-gray-200",
    ].join(" ");

  return (
    <div className="bg-gradient-to-b from-emerald-50/40 via-zinc-200 to-zinc-200 overflow-x-clip">
      {/* ==================== NAVBAR ==================== */}
      <nav className="fixed top-0 inset-x-0 z-50 bg-zinc-200/95 backdrop-blur-md border-b border-gray-200 w-full">
        <div className="w-full px-4 sm:px-6 md:px-5 lg:px-8 xl:px-10 2xl:px-12">
          <div className="min-h-24 md:min-h-28 lg:min-h-32 py-4 md:py-5 flex items-center justify-between gap-3 md:gap-4 lg:gap-6">
            <div className="flex min-w-0 flex-1 items-center justify-start gap-3 md:gap-4 lg:gap-6">
              <Link
                href="/"
                className="flex shrink-0 items-center cursor-pointer rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
              >
                <div className="bg-[#002D62] text-white font-bold text-2xl md:text-3xl lg:text-[2.25rem] px-7 py-3 md:px-8 md:py-3.5 lg:px-9 lg:py-4 tracking-[-1px]">
                  NIERS
                </div>
              </Link>

              <div className="hidden min-w-0 lg:flex items-center gap-4 lg:gap-6">
                <button
                  type="button"
                  onClick={() => scrollToSection("why-choose")}
                  className={desktopSectionNavClass("why-choose")}
                >
                  About NIERS
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("national-disaster")}
                  className={desktopSectionNavClass("national-disaster")}
                >
                  National Disasters
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("how-it-works")}
                  className={desktopSectionNavClass("how-it-works")}
                >
                  How It Works
                </button>
              </div>
            </div>

            <div className="flex shrink-0 items-center justify-end gap-4 md:gap-5 lg:gap-6 md:pl-1 lg:pl-2">
              <div
                className="hidden lg:flex bg-gray-100 rounded-full p-2"
                role="group"
                aria-label="Language"
              >
                <button
                  type="button"
                  className={langToggleClass("en")}
                  aria-pressed={lang === "en"}
                  onClick={() => setLang("en")}
                >
                  EN
                </button>
                <button
                  type="button"
                  className={langToggleClass("bn")}
                  aria-pressed={lang === "bn"}
                  onClick={() => setLang("bn")}
                >
                  বাংলা
                </button>
              </div>

              <div className="hidden lg:flex items-center gap-4">
                <Link
                  href="/auth/login"
                  className="cursor-pointer px-7 py-3 md:px-8 md:py-3.5 border-2 border-primary-600 rounded-2xl text-base lg:text-lg font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:text-primary-700 hover:bg-gray-50"
                >
                  Login
                </Link>
                <Link
                  href="/auth/register"
                  className="cursor-pointer px-7 py-3 md:px-8 md:py-3.5 bg-[#002D62] hover:bg-[#001F4A] text-white text-base lg:text-lg font-semibold rounded-2xl transition-colors"
                >
                  Register
                </Link>
              </div>

              <button
                type="button"
                id="mobile-menu-button"
                aria-expanded={isMobileMenuOpen}
                aria-controls="mobile-nav-panel"
                onClick={() => setIsMobileMenuOpen((o) => !o)}
                className="lg:hidden cursor-pointer p-2.5 rounded-lg text-gray-700 transition-colors hover:bg-gray-100"
              >
                <span className="sr-only">
                  {isMobileMenuOpen ? "Close menu" : "Open menu"}
                </span>
                {isMobileMenuOpen ? (
                  <X className="w-6 h-6" aria-hidden />
                ) : (
                  <Menu className="w-6 h-6" aria-hidden />
                )}
              </button>
            </div>
          </div>
        </div>

        {isMobileMenuOpen && (
          <motion.div
            id="mobile-nav-panel"
            role="region"
            aria-labelledby="mobile-menu-button"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18 }}
            className="lg:hidden border-t border-gray-200 bg-zinc-200"
          >
            <Container>
              <div className="py-5 space-y-1">
                <div className="pb-4 mb-2 border-b border-gray-100">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                    Language
                  </p>
                  <div
                    className="flex bg-gray-100 rounded-full p-1.5 w-fit"
                    role="group"
                    aria-label="Language"
                  >
                    <button
                      type="button"
                      className={langToggleClass("en")}
                      aria-pressed={lang === "en"}
                      onClick={() => setLang("en")}
                    >
                      EN
                    </button>
                    <button
                      type="button"
                      className={langToggleClass("bn")}
                      aria-pressed={lang === "bn"}
                      onClick={() => setLang("bn")}
                    >
                      বাংলা
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => scrollToSection("why-choose")}
                  className={`${mobileSectionNavClass("why-choose")} block w-full text-left py-3`}
                >
                  About NIERS
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("national-disaster")}
                  className={`${mobileSectionNavClass("national-disaster")} block w-full text-left py-3`}
                >
                  National Disasters
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("how-it-works")}
                  className={`${mobileSectionNavClass("how-it-works")} block w-full text-left py-3`}
                >
                  How It Works
                </button>

                <div className="pt-4 mt-2 border-t border-gray-200 flex flex-col gap-3">
                  <Link
                    href="/auth/login"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="cursor-pointer w-full py-3.5 text-center text-base font-semibold text-primary-600 border-2 border-primary-600 rounded-2xl transition-colors hover:border-primary-700 hover:text-primary-700 hover:bg-gray-50"
                  >
                    Login
                  </Link>
                  <Link
                    href="/auth/register"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="cursor-pointer w-full py-3.5 text-center text-base font-semibold bg-[#002D62] text-white rounded-2xl transition-colors hover:bg-[#001F4A]"
                  >
                    Register
                  </Link>
                </div>
              </div>
            </Container>
          </motion.div>
        )}
      </nav>

      {/* ==================== HERO SECTION ==================== */}
      <header className="relative min-h-screen w-full flex items-center overflow-hidden">
        {/* Background photo - CORRECTED */}
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-80"
          style={{
            backgroundImage: "url('/images/niers-bg.webp')",
          }}
        />
        {/* Blue shadow overlay — full hero: base tint + edge vignette */}
        <div
          className="absolute inset-0 pointer-events-none"
          aria-hidden
          style={{
            background:
              "radial-gradient(ellipse 125% 115% at 50% 42%, rgba(0,45,98,0) 48%, rgba(0,45,98,0.72) 100%), rgba(0,45,98,0.44)",
          }}
        />

        {/* Same width + padding pattern as Container so hero aligns with navbar / sections */}
        <div className="relative z-10 w-full">
          <div className="w-full max-w-screen-2xl mx-auto px-6 md:px-8">
            <div className="pt-36 md:pt-40 lg:pt-44 flex flex-col lg:flex-row items-start lg:items-center gap-12">
              {/* Focus card */}
              <RevealOnScroll className="bg-[#002D62] text-white rounded-3xl shadow-2xl border-l-4 w-full lg:w-auto shrink-0 p-6 sm:p-8 md:p-10 lg:p-12 xl:p-14 max-w-md sm:max-w-lg md:max-w-xl lg:max-w-xl xl:max-w-2xl 2xl:max-w-3xl min-h-72 md:min-h-[20rem] lg:min-h-[23rem] xl:min-h-[26rem] 2xl:min-h-[30rem]">
                <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-[1.1] mb-6">
                  NATIONAL INTEGRATED EMERGENCY RESPONSE SYSTEM
                </h2>
                <p className="text-white/90 text-lg sm:text-xl xl:text-xl leading-relaxed">
                  Centralized citizen reporting, 999 call intake, and
                  coordinated disaster response for Bangladesh.
                </p>
              </RevealOnScroll>
            </div>
          </div>
        </div>
      </header>

      {/* ==================== 999 EMERGENCY SQUARE CARD ==================== */}
      {/* ==================== 999 EMERGENCY SQUARE CARD ==================== */}
      <section className="w-full py-10 bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]">
        <Container>
          <RevealOnScroll className="bg-zinc-200 rounded-3xl shadow-lg flex justify-center px-6 py-12 md:px-8 md:py-14">
            <div className="max-w-[380px] w-full bg-gradient-to-br from-[#DA291C] to-[#B71C1C] rounded-3xl p-8 shadow-2xl text-center relative flex flex-col items-center">
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 w-16 h-16 bg-zinc-200 rounded-full flex items-center justify-center shadow-xl">
                <Phone className="w-9 h-9 text-[#DA291C]" />
              </div>
              <div className="mt-10 flex w-full flex-col items-center">
                <div className="text-7xl font-black text-white tracking-tighter">
                  999
                </div>
                <div className="text-white text-xl font-semibold mt-1">
                  Emergency Helpline
                </div>
                <div className="text-white/90 text-sm mt-1">
                  For life-threatening emergencies only
                </div>
              </div>
              <div className="h-px w-full max-w-[240px] bg-zinc-200/30 my-8" />
              <div className="flex w-full flex-col items-center gap-4">
                <div className="flex items-center justify-center gap-3 text-white/90 text-sm">
                  <span aria-hidden>🕒</span>
                  <span>Available 24/7</span>
                </div>
                <div className="flex items-center justify-center gap-3 text-white/90 text-sm">
                  <span aria-hidden>🛡️</span>
                  <span>Free of charge</span>
                </div>
              </div>
            </div>
          </RevealOnScroll>
        </Container>
      </section>

      {/* ==================== QUICK STATS BAR ==================== */}
      <section className="w-full py-10 bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]">
        <Container>
          <RevealOnScroll className="bg-zinc-200 rounded-3xl shadow-lg grid grid-cols-2 lg:grid-cols-4 divide-x divide-gray-100">
            <div className="p-6 text-center">
              <div className="w-10 h-10 mx-auto bg-[#002D62]/10 rounded-2xl flex items-center justify-center mb-4">
                <Users2 className="w-6 h-6 text-[#002D62]" />
              </div>
              <div className="text-4xl font-bold text-[#002D62]">170M+</div>
              <div className="text-gray-500 text-sm mt-1">Citizens Covered</div>
            </div>
            <div className="p-6 text-center">
              <div className="w-10 h-10 mx-auto bg-[#006747]/10 rounded-2xl flex items-center justify-center mb-4">
                <Building2 className="w-6 h-6 text-[#006747]" />
              </div>
              <div className="text-4xl font-bold text-[#006747]">50+</div>
              <div className="text-gray-500 text-sm mt-1">Partner Agencies</div>
            </div>
            <div className="p-6 text-center">
              <div className="w-10 h-10 mx-auto bg-[#DA291C]/10 rounded-2xl flex items-center justify-center mb-4">
                <Ambulance className="w-6 h-6 text-[#DA291C]" />
              </div>
              <div className="text-4xl font-bold text-[#DA291C]">24/7</div>
              <div className="text-gray-500 text-sm mt-1">
                Emergency Response
              </div>
            </div>
            <div className="p-6 text-center">
              <div className="w-10 h-10 mx-auto bg-[#002D62]/10 rounded-2xl flex items-center justify-center mb-4">
                <ClipboardCheck className="w-6 h-6 text-[#002D62]" />
              </div>
              <div className="text-4xl font-bold text-[#002D62]">1M+</div>
              <div className="text-gray-500 text-sm mt-1">Cases Resolved</div>
            </div>
          </RevealOnScroll>
        </Container>
      </section>

      {/* ==================== WHY CHOOSE NIERS ==================== */}
      <section
        id="why-choose"
        className="scroll-mt-36 md:scroll-mt-40 lg:scroll-mt-44 w-full py-16 bg-[#F0F7F4]"
      >
        <Container>
          <RevealOnScroll className="text-center mb-12">
            <h2 className="text-4xl font-bold text-[#002D62]">
              Why Choose NIERS?
            </h2>
          </RevealOnScroll>
          <div className="grid md:grid-cols-3 gap-6">
            {[
              {
                icon: Shield,
                title: "Unified Platform",
                desc: "Citizen reports and 999 calls in one system",
              },
              {
                icon: MapPin,
                title: "Real-time Tracking",
                desc: "Live location and dispatch visibility",
              },
              {
                icon: Users,
                title: "Multi-Agency Coordination",
                desc: "Police, Fire, Medical & Disaster teams",
              },
              {
                icon: Bell,
                title: "Instant Notifications",
                desc: "Official updates for every case",
              },
              {
                icon: BarChart3,
                title: "Data-Driven Response",
                desc: "Analytics for faster decisions",
              },
              {
                icon: FileText,
                title: "Official Records",
                desc: "Complete audit trail",
              },
            ].map((item, index) => (
              <RevealOnScroll
                key={item.title}
                delay={index * 0.06}
                className="bg-zinc-200 p-8 rounded-3xl border border-gray-200 hover:shadow-xl transition-shadow"
              >
                <div className="w-12 h-12 bg-[#006747]/10 text-[#006747] rounded-2xl flex items-center justify-center mb-6">
                  <item.icon className="w-7 h-7" />
                </div>
                <h3 className="text-xl font-semibold text-[#002D62] mb-3">
                  {item.title}
                </h3>
                <p className="text-gray-600">{item.desc}</p>
              </RevealOnScroll>
            ))}
          </div>
        </Container>
      </section>

      {/* ==================== HOW NIERS WORKS ==================== */}
      {/* ==================== HOW NIERS WORKS - WITH ARROWS ==================== */}
      <section
        id="how-it-works"
        className="scroll-mt-36 md:scroll-mt-40 lg:scroll-mt-44 w-full py-16 bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]"
      >
        <Container>
          <div className="bg-zinc-200 rounded-3xl shadow-lg px-6 py-12 md:px-8 md:py-14">
          <RevealOnScroll className="text-center mb-12">
            <span className="text-[#006747] font-semibold tracking-widest">
              SIMPLE PROCESS
            </span>
            <h2 className="text-4xl font-bold text-[#002D62] mt-2">
              How NIERS Works
            </h2>
            <p className="text-gray-600 mt-3">
              Get the help you need in three simple steps
            </p>
          </RevealOnScroll>

          {/* Desktop: Horizontal layout with arrows */}
          <div className="hidden md:flex items-stretch justify-between gap-4 max-w-5xl mx-auto">
            {/* Step 1 */}
            <RevealOnScroll className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15">
              <Phone className="w-12 h-12 shrink-0 text-[#DA291C] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">Call 999</h3>
              <p className="text-gray-600 mt-2">For urgent emergencies</p>
              <p className="text-xs text-gray-500">(No login needed)</p>
            </RevealOnScroll>

            <div className="flex items-center self-center">
              <ArrowRight className="w-9 h-9 text-[#006747]" />
            </div>

            {/* Step 2 */}
            <RevealOnScroll
              delay={0.08}
              className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15"
            >
              <FileText className="w-12 h-12 shrink-0 text-[#006747] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">
                Register &amp; Submit Report
              </h3>
              <p className="text-gray-600 mt-2">For non-emergency issues</p>
            </RevealOnScroll>

            <div className="flex items-center self-center">
              <ArrowRight className="w-9 h-9 text-[#006747]" />
            </div>

            {/* Step 3 */}
            <RevealOnScroll
              delay={0.16}
              className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15"
            >
              <BarChart3 className="w-12 h-12 shrink-0 text-[#002D62] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">
                Track &amp; Get Updates
              </h3>
              <p className="text-gray-600 mt-2">
                Dispatcher reviews and keeps you informed
              </p>
            </RevealOnScroll>
          </div>

          {/* Mobile: Vertical layout with down arrows */}
          <div className="md:hidden space-y-8 max-w-md mx-auto">
            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15">
              <Phone className="w-12 h-12 shrink-0 text-[#DA291C] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">Call 999</h3>
              <p className="text-gray-600 mt-2">For urgent emergencies</p>
              <p className="text-xs text-gray-500">(No login needed)</p>
            </RevealOnScroll>

            <div className="flex justify-center">
              <ChevronDown className="w-8 h-8 text-[#006747]" />
            </div>

            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15">
              <FileText className="w-12 h-12 shrink-0 text-[#006747] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">
                Register &amp; Submit Report
              </h3>
              <p className="text-gray-600 mt-2">For non-emergency issues</p>
            </RevealOnScroll>

            <div className="flex justify-center">
              <ChevronDown className="w-8 h-8 text-[#006747]" />
            </div>

            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-8 text-center ring-1 ring-[#006747]/15">
              <BarChart3 className="w-12 h-12 shrink-0 text-[#002D62] mb-4" />
              <h3 className="font-semibold text-xl text-[#002D62]">
                Track &amp; Get Updates
              </h3>
              <p className="text-gray-600 mt-2">
                Dispatcher reviews and keeps you informed
              </p>
            </RevealOnScroll>
          </div>
          </div>
        </Container>
      </section>

      {/* ==================== DISASTERS & NATIONAL EMERGENCIES CARD ==================== */}
      <section
        id="national-disaster"
        className="scroll-mt-36 md:scroll-mt-40 lg:scroll-mt-44 w-full py-16 bg-[#EFF6FF]"
      >
        <Container>
          <RevealOnScrollButton className="mx-auto w-full max-w-4xl text-left rounded-3xl border-2 border-[#006747]/35 bg-gradient-to-br from-emerald-100/95 via-emerald-50/90 to-[#c5e3d4] p-8 shadow-lg shadow-[#006747]/15 transition-colors hover:border-[#006747]/55 md:p-10 flex flex-col lg:flex-row items-start gap-6 lg:gap-8 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[#006747] focus-visible:ring-offset-2 focus-visible:ring-offset-[#EFF6FF]">
            <div className="flex h-20 w-20 shrink-0 self-start items-center justify-center rounded-2xl bg-[#DA291C]">
              <AlertTriangle className="h-10 w-10 text-white" aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <span className="inline-flex items-center gap-2 rounded-full bg-[#DA291C]/10 px-4 py-1 text-sm font-bold text-[#DA291C]">
                IMPORTANT
              </span>
              <h2 className="mt-4 text-3xl font-bold text-[#002D62]">
                Disasters &amp; National Emergencies
              </h2>
              <p className="mt-4 text-gray-600">
                Stay informed about active national emergencies, affected areas,
                shelter locations, and relief operations. NIERS coordinates
                multi-agency response during large-scale disasters.
              </p>
              <div className="mt-6 flex flex-wrap justify-start gap-3">
                <span className="inline-flex items-center rounded-full bg-[#006747]/10 px-3 py-1 text-sm font-medium text-[#006747]">
                  Flood Response
                </span>
                <span className="inline-flex items-center rounded-full bg-[#006747]/10 px-3 py-1 text-sm font-medium text-[#006747]">
                  Shelter Updates
                </span>
                <span className="inline-flex items-center rounded-full bg-[#006747]/10 px-3 py-1 text-sm font-medium text-[#006747]">
                  Relief Distribution
                </span>
              </div>
            </div>
          </RevealOnScrollButton>
        </Container>
      </section>

      {/* ==================== FOOTER ==================== */}
      <footer className="w-full border-t-4 border-[#006747] bg-[#0F172A] text-white py-16">
        <Container>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-12">
            {/* Column 1 - Branding + About Bangladesh */}
            <div className="md:col-span-5">
              <div className="flex items-center gap-3 mb-6">
                <span className="text-2xl font-bold">NIERS</span>
              </div>
              <h3 className="text-white font-semibold mb-3">
                About Bangladesh
              </h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Bangladesh faces unique emergency challenges due to its dense
                population, river-based geography, coastal exposure, and monsoon
                climate. NIERS provides a centralized platform to coordinate
                emergency response across multiple agencies.
              </p>
            </div>

            {/* Column 2 - Quick Links */}
            <div className="md:col-span-3">
              <h3 className="font-semibold mb-4">Quick Links</h3>
              <div className="space-y-3 text-sm text-gray-400">
                <div>About NIERS</div>
                <div>How NIERS Works</div>
                <div>For Citizens</div>
                <div>For Officials</div>
                <div>National Disasters</div>
                <div>Privacy Policy</div>
                <div>Terms of Service</div>
              </div>
            </div>

            {/* Column 3 - Contact */}
            <div className="md:col-span-4">
              <h3 className="font-semibold mb-4">Contact</h3>
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="w-9 h-9 bg-[#DA291C] rounded-xl flex items-center justify-center flex-shrink-0">
                    <Phone className="h-5 w-5 text-white" aria-hidden />
                  </div>
                  <div>
                    <div className="text-xs text-gray-400">Emergency</div>
                    <div className="font-bold text-xl">999</div>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="w-9 h-9 bg-[#006747] rounded-xl flex items-center justify-center flex-shrink-0">
                    <Mail className="h-5 w-5 text-white" aria-hidden />
                  </div>
                  <div>
                    <div className="text-xs text-gray-400">Email</div>
                    <div className="font-medium">info@niers.gov.bd</div>
                  </div>
                </div>
              </div>
              <div className="mt-10 pt-6 border-t border-gray-700 text-xs text-gray-400">
                For Officials / Dispatchers
                <br />
                Ministry of Disaster Management and Relief
                <br />
                Government of the People's Republic of Bangladesh
              </div>
            </div>
          </div>
        </Container>
      </footer>
    </div>
  );
}
