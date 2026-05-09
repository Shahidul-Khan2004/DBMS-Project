// components/layout/Sidebar.tsx
"use client";

import Link from "next/link";
import { Home, FileText, PlusCircle, Users, AlertTriangle, BarChart3 } from "lucide-react";

export default function Sidebar() {
  return (
    <div className="w-64 bg-white border-r flex flex-col shadow-sm">
      <div className="p-6 border-b">
        <h1 className="text-2xl font-bold text-blue-800 tracking-tight">NIERS</h1>
      </div>

      <nav className="flex-1 px-3 py-6 space-y-1">
        <Link href="/dashboard/citizen" 
          className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-blue-50 rounded-xl font-medium transition-colors">
          <Home className="w-5 h-5" />
          Dashboard
        </Link>
        
        <Link href="/dashboard/citizen/report-new" 
          className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-blue-50 rounded-xl font-medium transition-colors">
          <PlusCircle className="w-5 h-5" />
          Submit Report
        </Link>

        <Link href="/dashboard/citizen/reports" 
          className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-blue-50 rounded-xl font-medium transition-colors">
          <FileText className="w-5 h-5" />
          My Reports
        </Link>

        {/* Dispatcher / Admin links will appear based on role later */}
      </nav>

      <div className="p-4 border-t text-xs text-gray-500 text-center">
        Bangladesh 999 Emergency System
      </div>
    </div>
  );
}