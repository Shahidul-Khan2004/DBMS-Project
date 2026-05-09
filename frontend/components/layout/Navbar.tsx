// components/layout/Navbar.tsx
"use client";

import { LogOut, Bell, User } from "lucide-react";

export default function Navbar() {
  return (
    <nav className="h-14 bg-white border-b shadow-sm px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="bg-blue-800 text-white text-xl font-bold px-4 py-1 rounded">
          NIERS
        </div>
        <span className="text-gray-700 text-sm font-medium hidden md:block">
          National Integrated Emergency Response System
        </span>
      </div>

      <div className="flex items-center gap-6">
        <button className="relative">
          <Bell className="w-5 h-5 text-gray-600" />
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[10px] w-4 h-4 rounded-full flex items-center justify-center">
            3
          </span>
        </button>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-sm font-medium text-gray-800">John Doe</p>
            <p className="text-xs text-gray-500">Citizen</p>
          </div>
          <div className="w-8 h-8 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center">
            <User className="w-5 h-5" />
          </div>
        </div>

        <button className="flex items-center gap-2 text-gray-600 hover:text-red-600 transition-colors">
          <LogOut className="w-5 h-5" />
        </button>
      </div>
    </nav>
  );
}