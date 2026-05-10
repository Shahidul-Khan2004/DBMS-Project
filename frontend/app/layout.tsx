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
    <html lang="en">
      <body className={`${inter.className} bg-gray-50 antialiased`}>
        <main className="flex-1 overflow-auto bg-gray-50 p-6">{children}</main>
      </body>
    </html>
  );
}
