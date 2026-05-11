// components/layout/Logo.tsx
import Image from "next/image";
import Link from "next/link";

export default function Logo() {
  return (
    <Link href="/" className="flex items-center">
      <Image
        src="/images/niers-logo.jpg"
        alt="NIERS Logo"
        width={200}
        height={70}
        priority
        className="hover:scale-105 transition-transform"
      />
    </Link>
  );
}