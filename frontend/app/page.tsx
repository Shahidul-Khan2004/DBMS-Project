// app/page.tsx
"use client";

import { motion } from "framer-motion";
import {
  Phone,
  Shield,
  MapPin,
  Users,
  Bell,
  FileText,
  BarChart3,
  Menu,
  X,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";

function Container({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-w-screen-2xl mx-auto px-6 md:px-8">
      {children}
    </div>
  );
}

export default function Home() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const scrollToSection = (id: string) => {
    setIsMobileMenuOpen(false);

    document.getElementById(id)?.scrollIntoView({
      behavior: "smooth",
    });
  };

  return (
    <div className="bg-gray-50">
      {/* HERO */}
      <header className="relative min-h-screen w-full flex items-center overflow-hidden">
        {/* Background image */}
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{
            backgroundImage:
              "url('https://picsum.photos/id/1015/2000/1200')",
          }}
        />

        {/* Overlay */}
        <div className="absolute inset-0 bg-gradient-to-r from-[#002D62]/50 to-black/20" />

        {/* NAVBAR */}
        <nav className="fixed top-0 inset-x-0 z-50 bg-white/95 backdrop-blur-md border-b border-gray-200">
          <Container>
            <div className="h-16 flex items-center justify-between">
              {/* Logo */}
              <Link href="/" className="flex items-center">
                <div className="bg-[#002D62] text-white font-bold text-2xl px-5 py-2 tracking-tight rounded-lg">
                  NIERS
                </div>
              </Link>

              {/* Desktop Nav */}
              <div className="hidden md:flex items-center gap-8 text-sm font-medium text-gray-700">
                <button
                  onClick={() => scrollToSection("how-it-works")}
                  className="hover:text-[#002D62] transition-colors"
                >
                  How It Works
                </button>

                <button
                  onClick={() => scrollToSection("why-choose")}
                  className="hover:text-[#002D62] transition-colors"
                >
                  For Citizens
                </button>

                <button
                  onClick={() => scrollToSection("national-disaster")}
                  className="hover:text-[#002D62] transition-colors"
                >
                  National Disasters
                </button>

                <button
                  onClick={() => scrollToSection("why-choose")}
                  className="hover:text-[#002D62] transition-colors"
                >
                  About NIERS
                </button>
              </div>

              {/* Right Side */}
              <div className="flex items-center gap-3">
                {/* Language Switch */}
                <div className="hidden sm:flex bg-gray-100 rounded-full p-1 text-xs font-medium">
                  <button className="px-4 py-1.5 bg-[#002D62] text-white rounded-full">
                    EN
                  </button>

                  <button className="px-4 py-1.5 text-gray-700 hover:bg-gray-200 rounded-full transition-colors">
                    বাংলা
                  </button>
                </div>

                {/* Desktop Auth Buttons */}
                <div className="hidden md:flex items-center gap-3">
                  <Link
                    href="/auth/login"
                    className="px-5 py-2 border border-gray-300 hover:border-gray-400 rounded-2xl text-sm transition-colors"
                  >
                    Login
                  </Link>

                  <Link
                    href="/auth/register"
                    className="px-5 py-2 bg-[#002D62] hover:bg-[#001F4A] text-white text-sm font-semibold rounded-2xl transition-colors"
                  >
                    Register
                  </Link>
                </div>

                {/* Mobile Menu Button */}
                <button
                  onClick={() =>
                    setIsMobileMenuOpen(!isMobileMenuOpen)
                  }
                  className="md:hidden p-2 text-gray-700"
                >
                  {isMobileMenuOpen ? (
                    <X className="w-6 h-6" />
                  ) : (
                    <Menu className="w-6 h-6" />
                  )}
                </button>
              </div>
            </div>
          </Container>

          {/* Mobile Menu */}
          {isMobileMenuOpen && (
            <div className="md:hidden border-t border-gray-200 bg-white">
              <Container>
                <div className="py-6 space-y-5">
                  <button
                    onClick={() => scrollToSection("how-it-works")}
                    className="block w-full text-left text-gray-700"
                  >
                    How It Works
                  </button>

                  <button
                    onClick={() => scrollToSection("why-choose")}
                    className="block w-full text-left text-gray-700"
                  >
                    For Citizens
                  </button>

                  <button
                    onClick={() =>
                      scrollToSection("national-disaster")
                    }
                    className="block w-full text-left text-gray-700"
                  >
                    National Disasters
                  </button>

                  <button
                    onClick={() => scrollToSection("why-choose")}
                    className="block w-full text-left text-gray-700"
                  >
                    About NIERS
                  </button>

                  {/* Mobile Auth */}
                  <div className="pt-5 border-t border-gray-200 flex flex-col gap-3">
                    <Link
                      href="/auth/login"
                      className="w-full py-3 text-center border border-gray-300 rounded-2xl"
                    >
                      Login
                    </Link>

                    <Link
                      href="/auth/register"
                      className="w-full py-3 text-center bg-[#002D62] text-white rounded-2xl"
                    >
                      Register
                    </Link>
                  </div>
                </div>
              </Container>
            </div>
          )}
        </nav>

        {/* HERO CONTENT */}
        <Container>
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="relative z-10 pt-24 text-white max-w-2xl"
          >
            <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold leading-tight mb-6">
              National Integrated Emergency Response System
            </h1>

            <p className="text-lg md:text-xl text-blue-100 mb-8 max-w-xl">
              Centralized citizen reporting, 999 call intake,
              and coordinated disaster response for Bangladesh.
            </p>

            <div className="flex flex-col sm:flex-row gap-4">
              <Link
                href="/auth/register"
                className="px-7 py-3.5 bg-white text-[#002D62] font-semibold rounded-2xl text-base hover:bg-gray-100 transition-colors text-center"
              >
                Register Now
              </Link>

              <Link
                href="/auth/login"
                className="px-7 py-3.5 border-2 border-white text-white font-semibold rounded-2xl text-base hover:bg-white/10 transition-colors text-center"
              >
                Login
              </Link>
            </div>
          </motion.div>
        </Container>
      </header>

      {/* EMERGENCY STRIP */}
      <section className="w-full bg-red-600 text-white py-6">
        <Container>
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-5">
              <Phone className="w-12 h-12" />

              <div>
                <div className="text-5xl font-black tracking-tighter">
                  999
                </div>

                <div className="text-base">
                  Emergency Hotline
                </div>
              </div>
            </div>

            <button className="bg-white text-red-600 px-8 py-3 rounded-2xl font-semibold text-base hover:bg-gray-100 transition-colors">
              Call 999 Now
            </button>
          </div>
        </Container>
      </section>

      {/* STATS */}
      <section className="w-full py-10 bg-white">
        <Container>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            {[
              {
                value: "50K+",
                label: "Emergency Calls",
              },
              {
                value: "1.2M+",
                label: "Registered Citizens",
              },
              {
                value: "500+",
                label: "Active Dispatchers",
              },
              {
                value: "24/7",
                label: "Response Coverage",
              },
            ].map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
              >
                <div className="text-4xl font-bold text-[#002D62]">
                  {stat.value}
                </div>

                <div className="text-gray-600 text-sm mt-2">
                  {stat.label}
                </div>
              </motion.div>
            ))}
          </div>
        </Container>
      </section>

      {/* WHY CHOOSE */}
      <section
        id="why-choose"
        className="w-full py-16 bg-gray-50"
      >
        <Container>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <h2 className="text-4xl font-bold text-[#002D62]">
              Why Choose NIERS?
            </h2>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
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
            ].map((item, i) => (
              <motion.div
                key={item.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="bg-white p-6 rounded-3xl border border-gray-200 hover:shadow-xl transition-all duration-300"
              >
                <div className="w-12 h-12 bg-[#006747]/10 text-[#006747] rounded-2xl flex items-center justify-center mb-5">
                  <item.icon className="w-6 h-6" />
                </div>

                <h3 className="text-xl font-semibold text-[#002D62] mb-3">
                  {item.title}
                </h3>

                <p className="text-gray-600 text-sm leading-relaxed">
                  {item.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </Container>
      </section>

      {/* FOOTER */}
      <footer className="w-full bg-[#002D62] text-white py-10">
        <Container>
          <div className="text-center">
            <p className="text-white/80 text-sm">
              National Integrated Emergency Response System
            </p>

            <p className="text-xs text-white/50 mt-3">
              © 2026 NIERS — Government of the People’s
              Republic of Bangladesh
            </p>
          </div>
        </Container>
      </footer>
    </div>
  );
}