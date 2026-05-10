// app/layout.tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

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
    <html lang="en" className="min-h-screen">
      <body
        className={`${inter.className} min-h-screen bg-gray-50 antialiased`}
      >
        <main className="min-h-screen bg-gray-50">{children}</main>
      </body>
    </html>
  );
}
