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
  AlertTriangle,
  Users2,
  Building2,
  Ambulance,
  ClipboardCheck,
  ArrowRight,
  ChevronDown,
} from "lucide-react";
import { useState } from "react";
import {
  RevealOnScroll,
  RevealOnScrollButton,
} from "@/components/RevealOnScroll";
import {
  LandingNavbar,
  type LandingSectionId,
} from "@/components/layout/LandingNavbar";
import { NationalDisasterHeroAlert } from "@/components/NationalDisasterHeroAlert";

function Container({ children }: { children: React.ReactNode }) {
  return <div className="landing-container">{children}</div>;
}

export default function Home() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [selectedSection, setSelectedSection] =
    useState<LandingSectionId | null>(null);
  const [lang, setLang] = useState<"en" | "bn">("en");

  return (
    <div className="landing-page bg-gradient-to-b from-emerald-50/40 via-zinc-200 to-zinc-200 overflow-x-clip">
      <LandingNavbar
        isMobileMenuOpen={isMobileMenuOpen}
        setIsMobileMenuOpen={setIsMobileMenuOpen}
        selectedSection={selectedSection}
        setSelectedSection={setSelectedSection}
        lang={lang}
        setLang={setLang}
      />
      <header className="relative mt-[var(--nav-h)] min-h-[calc(100svh-var(--nav-h))] w-full flex items-center overflow-hidden">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-80"
          style={{
            backgroundImage: "url('/images/niers-bg.webp')",
          }}
        />  
        <div
          className="absolute inset-0 pointer-events-none"
          aria-hidden
          style={{
            background:
              "radial-gradient(ellipse 125% 115% at 50% 42%, rgba(0,45,98,0) 48%, rgba(0,45,98,0.72) 100%), rgba(0,45,98,0.44)",
          }}
        />
        <div className="absolute left-0 right-0 top-[clamp(1.25rem,6vh,4rem)] z-20">
          <NationalDisasterHeroAlert />
        </div>
        <div className="relative z-10 w-full">
          <div className="landing-container">
            <div className="flex flex-col lg:flex-row items-start lg:items-center gap-[var(--landing-stack-gap)]">

              <RevealOnScroll className="bg-[#002D62] text-white rounded-3xl shadow-2xl border-l-4 w-full lg:w-auto shrink-0 p-[var(--card-p)] max-w-md sm:max-w-lg md:max-w-xl lg:max-w-xl xl:max-w-2xl 2xl:max-w-2xl min-h-[clamp(14rem,28vh,22rem)]">
                <h2 className="landing-text-hero font-bold leading-[1.1] mb-[clamp(1rem,2vh,1.5rem)]">
                  NATIONAL INTEGRATED EMERGENCY RESPONSE SYSTEM
                </h2>
                <p className="text-white/90 landing-text-body leading-relaxed">
                  Centralized citizen reporting, 999 call intake, and
                  coordinated disaster response for Bangladesh.
                </p>
              </RevealOnScroll>
            </div>
          </div>
        </div>
      </header>
      
      <section className="w-full py-[var(--landing-section-py-sm)] bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]">
        <Container>
          <RevealOnScroll className="bg-zinc-200 rounded-3xl shadow-lg flex justify-center p-[var(--card-p)]">
            <div className="max-w-[340px] w-full bg-gradient-to-br from-[#DA291C] to-[#B71C1C] rounded-3xl p-[var(--card-p)] shadow-2xl text-center relative flex flex-col items-center">
              <div className="absolute -top-5 left-1/2 -translate-x-1/2 w-14 h-14 bg-zinc-200 rounded-full flex items-center justify-center shadow-xl">
                <Phone className="w-8 h-8 text-[#DA291C]" />
              </div>
              <div className="mt-8 flex w-full flex-col items-center">
                <div className="landing-text-999 font-black text-white tracking-tighter">
                  999
                </div>
                <div className="text-white landing-text-card-title font-semibold mt-1">
                  Emergency Helpline
                </div>
                <div className="text-white/90 text-sm mt-1">
                  For life-threatening emergencies only
                </div>
              </div>
              <div className="h-px w-full max-w-[240px] bg-zinc-200/30 my-6" />
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

      <section className="w-full py-[var(--landing-section-py-sm)] bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]">
        <Container>
          <RevealOnScroll className="bg-zinc-200 rounded-3xl shadow-lg grid grid-cols-2 lg:grid-cols-4 divide-x divide-gray-100">
            <div className="p-[var(--card-p)] text-center">
              <div className="w-9 h-9 mx-auto bg-[#002D62]/10 rounded-2xl flex items-center justify-center mb-3">
                <Users2 className="w-5 h-5 text-[#002D62]" />
              </div>
              <div className="landing-text-stat font-bold text-[#002D62]">170M+</div>
              <div className="text-gray-500 text-sm mt-1">Citizens Covered</div>
            </div>
            <div className="p-[var(--card-p)] text-center">
              <div className="w-9 h-9 mx-auto bg-[#006747]/10 rounded-2xl flex items-center justify-center mb-3">
                <Building2 className="w-5 h-5 text-[#006747]" />
              </div>
              <div className="landing-text-stat font-bold text-[#006747]">50+</div>
              <div className="text-gray-500 text-sm mt-1">Partner Agencies</div>
            </div>
            <div className="p-[var(--card-p)] text-center">
              <div className="w-9 h-9 mx-auto bg-[#DA291C]/10 rounded-2xl flex items-center justify-center mb-3">
                <Ambulance className="w-5 h-5 text-[#DA291C]" />
              </div>
              <div className="landing-text-stat font-bold text-[#DA291C]">24/7</div>
              <div className="text-gray-500 text-sm mt-1">
                Emergency Response
              </div>
            </div>
            <div className="p-[var(--card-p)] text-center">
              <div className="w-9 h-9 mx-auto bg-[#002D62]/10 rounded-2xl flex items-center justify-center mb-3">
                <ClipboardCheck className="w-5 h-5 text-[#002D62]" />
              </div>
              <div className="landing-text-stat font-bold text-[#002D62]">1M+</div>
              <div className="text-gray-500 text-sm mt-1">Cases Resolved</div>
            </div>
          </RevealOnScroll>
        </Container>
      </section>

      <section
        id="why-choose"
        className="scroll-mt-[var(--nav-h)] w-full py-[var(--section-y)] bg-[#F0F7F4]"
      >
        <Container>
          <RevealOnScroll className="text-center mb-[var(--landing-heading-gap)]">
            <h2 className="landing-text-section font-bold text-[#002D62]">
              Why Choose NIERS?
            </h2>
          </RevealOnScroll>
          <div className="grid md:grid-cols-3 gap-[var(--nav-gap)]">
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
                className="bg-zinc-200 p-[var(--card-p)] rounded-3xl border border-gray-200 hover:shadow-xl transition-shadow"
              >
                <div className="w-10 h-10 bg-[#006747]/10 text-[#006747] rounded-2xl flex items-center justify-center mb-4">
                  <item.icon className="w-6 h-6" />
                </div>
                <h3 className="landing-text-card-title font-semibold text-[#002D62] mb-2">
                  {item.title}
                </h3>
                <p className="text-gray-600">{item.desc}</p>
              </RevealOnScroll>
            ))}
          </div>
        </Container>
      </section>
      
      <section
        id="how-it-works"
        className="scroll-mt-[var(--nav-h)] w-full py-[var(--section-y)] bg-gradient-to-r from-emerald-50/50 via-[#EFF6FF] to-[#EFF6FF]"
      >
        <Container>
          <div className="bg-zinc-200 rounded-3xl shadow-lg p-[var(--card-p)]">
          <RevealOnScroll className="text-center mb-[var(--landing-heading-gap)]">
            <span className="text-[#006747] font-semibold tracking-widest">
              SIMPLE PROCESS
            </span>
            <h2 className="landing-text-section font-bold text-[#002D62] mt-2">
              How NIERS Works
            </h2>
            <p className="text-gray-600 mt-3">
              Get the help you need in three simple steps
            </p>
          </RevealOnScroll>

          <div className="hidden w-full items-stretch justify-between gap-4 md:flex">
            
            <RevealOnScroll className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15">
              <Phone className="w-10 h-10 shrink-0 text-[#DA291C] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">Call 999</h3>
              <p className="text-gray-600 mt-2">For urgent emergencies</p>
              <p className="text-xs text-gray-500">(No login needed)</p>
            </RevealOnScroll>

            <div className="flex items-center self-center">
              <ArrowRight className="w-8 h-8 text-[#006747]" />
            </div>
            
            <RevealOnScroll
              delay={0.08}
              className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15"
            >
              <FileText className="w-10 h-10 shrink-0 text-[#006747] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">
                Register &amp; Submit Report
              </h3>
              <p className="text-gray-600 mt-2">For non-emergency issues</p>
            </RevealOnScroll>

            <div className="flex items-center self-center">
              <ArrowRight className="w-8 h-8 text-[#006747]" />
            </div>

            <RevealOnScroll
              delay={0.16}
              className="flex-1 flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15"
            >
              <BarChart3 className="w-10 h-10 shrink-0 text-[#002D62] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">
                Track &amp; Get Updates
              </h3>
              <p className="text-gray-600 mt-2">
                Dispatcher reviews and keeps you informed
              </p>
            </RevealOnScroll>
          </div>

          <div className="w-full space-y-6 md:hidden">
            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15">
              <Phone className="w-10 h-10 shrink-0 text-[#DA291C] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">Call 999</h3>
              <p className="text-gray-600 mt-2">For urgent emergencies</p>
              <p className="text-xs text-gray-500">(No login needed)</p>
            </RevealOnScroll>

            <div className="flex justify-center">
              <ChevronDown className="w-8 h-8 text-[#006747]" />
            </div>

            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15">
              <FileText className="w-10 h-10 shrink-0 text-[#006747] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">
                Register &amp; Submit Report
              </h3>
              <p className="text-gray-600 mt-2">For non-emergency issues</p>
            </RevealOnScroll>

            <div className="flex justify-center">
              <ChevronDown className="w-8 h-8 text-[#006747]" />
            </div>

            <RevealOnScroll className="flex flex-col items-center bg-gradient-to-br from-emerald-50/90 to-[#EFF6FF] rounded-3xl p-[var(--card-p)] text-center ring-1 ring-[#006747]/15">
              <BarChart3 className="w-10 h-10 shrink-0 text-[#002D62] mb-3" />
              <h3 className="font-semibold landing-text-card-title text-[#002D62]">
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

      <section
        id="national-disaster"
        className="scroll-mt-[var(--nav-h)] w-full py-[var(--section-y)] bg-[#EFF6FF]"
      >
        <Container>
          <RevealOnScrollButton className="w-full text-left rounded-3xl border-2 border-[#006747]/35 bg-gradient-to-br from-emerald-100/95 via-emerald-50/90 to-[#c5e3d4] p-[var(--card-p)] shadow-lg shadow-[#006747]/15 transition-colors hover:border-[#006747]/55 flex flex-col lg:flex-row items-start gap-[var(--landing-stack-gap)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[#006747] focus-visible:ring-offset-2 focus-visible:ring-offset-[#EFF6FF]">
            <div className="flex h-16 w-16 shrink-0 self-start items-center justify-center rounded-2xl bg-[#DA291C]">
              <AlertTriangle className="h-8 w-8 text-white" aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <span className="inline-flex items-center gap-2 rounded-full bg-[#DA291C]/10 px-4 py-1 text-sm font-bold text-[#DA291C]">
                IMPORTANT
              </span>
              <h2 className="mt-4 landing-text-section-sm font-bold text-[#002D62]">
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

      <footer className="w-full border-t-4 border-[#006747] bg-[#0F172A] text-white py-[var(--section-y)]">
        <Container>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-[var(--landing-stack-gap)]">
            
            <div className="md:col-span-5">
              <div className="flex items-center gap-3 mb-4">
                <span className="landing-text-logo font-bold">NIERS</span>
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

            <div className="md:col-span-4">
              <h3 className="font-semibold mb-4">Contact</h3>
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="w-9 h-9 bg-[#DA291C] rounded-xl flex items-center justify-center flex-shrink-0">
                    <Phone className="h-5 w-5 text-white" aria-hidden />
                  </div>
                  <div>
                    <div className="text-xs text-gray-400">Emergency</div>
                    <div className="font-bold landing-text-card-title">999</div>
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
                Government of the People&apos;s Republic of Bangladesh
              </div>
            </div>
          </div>
        </Container>
      </footer>
    </div>
  );
}
