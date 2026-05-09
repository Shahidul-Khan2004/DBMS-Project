// app/layout.tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/layout/Navbar";           // we'll create this
import Sidebar from "@/components/layout/Sidebar";         // we'll create this

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "NIERS | National Integrated Emergency Response System",
  description: "Official emergency response & disaster coordination platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-gray-50 antialiased`}>
        <div className="flex h-screen overflow-hidden">
          {/* LEFT SIDEBAR - always visible on dashboards */}
          <Sidebar />

          {/* MAIN AREA */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* TOP NAV */}
            <Navbar />

            {/* PAGE CONTENT */}
            <main className="flex-1 overflow-auto bg-gray-50 p-6">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}