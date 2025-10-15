import * as React from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

interface URLProcess {
  orgUrl: string;
  score: number;
  label: string;
  country: string;
  firstSeen: string;
  timeSeen: string;
  timeStamp: string;
  verdict: "High Risk" | "Suspicious" | "Low";
}

const demoData: URLProcess[] = [
  {
    orgUrl: "http://uidai-verification.in",
    score: 91,
    label: "Phishing",
    country: "IN",
    firstSeen: "2025-09-20",
    timeSeen: "2025-10-08 10:42:21",
    timeStamp: "UIDAI",
    verdict: "High Risk",
  },
  {
    orgUrl: "https://irctc-ticketbook.net",
    score: 76,
    label: "Typosquat",
    country: "IN",
    firstSeen: "2025-09-18",
    timeSeen: "2025-10-08 10:44:09",
    timeStamp: "IRCTC",
    verdict: "Suspicious",
  },
  {
    orgUrl: "http://govt-pmkisanrefund.org",
    score: 89,
    label: "Phishing",
    country: "IN",
    firstSeen: "2025-09-22",
    timeSeen: "2025-10-08 10:45:17",
    timeStamp: "PM-Kisan",
    verdict: "High Risk",
  },
  {
    orgUrl: "https://income-taxupdate.co.in",
    score: 64,
    label: "Typosquat",
    country: "IN",
    firstSeen: "2025-09-25",
    timeSeen: "2025-10-08 10:46:55",
    timeStamp: "IncomeTax",
    verdict: "Suspicious",
  },
  {
    orgUrl: "http://mygov-portal.info",
    score: 51,
    label: "Typosquat",
    country: "IN",
    firstSeen: "2025-09-26",
    timeSeen: "2025-10-08 10:48:12",
    timeStamp: "MyGov",
    verdict: "High Risk",
  },
  {
    orgUrl: "https://axis-banklogin.net",
    score: 92,
    label: "Typosquat",
    country: "IN",
    firstSeen: "2025-09-23",
    timeSeen: "2025-10-08 10:50:10",
    timeStamp: "Axis Bank",
    verdict: "High Risk",
  },
  {
    orgUrl: "http://digilocker-access.org",
    score: 87,
    label: "Typosquat",
    country: "IN",
    firstSeen: "2025-09-27",
    timeSeen: "2025-10-08 10:52:31",
    timeStamp: "DigiLocker",
    verdict: "Low",
  },
];

export const URLProcessTable: React.FC = () => {
  const getVerdictVariant = (
    verdict: string
  ): "default" | "destructive" | "secondary" => {
    if (verdict === "High Risk") return "destructive";
    if (verdict === "Suspicious") return "secondary";
    return "default";
  };

  return (
    <div className="w-full">
      <Table>
        <TableHeader>
          <TableRow className="border-white/10 hover:bg-transparent">
            <TableHead className="text-gray-400 font-medium">Org URL</TableHead>
            <TableHead className="text-gray-400 font-medium">Score</TableHead>
            <TableHead className="text-gray-400 font-medium">Label</TableHead>
            <TableHead className="text-gray-400 font-medium">Country</TableHead>
            <TableHead className="text-gray-400 font-medium">First Seen</TableHead>
            <TableHead className="text-gray-400 font-medium">Time Seen</TableHead>
            <TableHead className="text-gray-400 font-medium">Time Stamp</TableHead>
            <TableHead className="text-gray-400 font-medium">Verdict</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {demoData.map((row, index) => (
            <TableRow key={index} className="border-white/5 hover:bg-white/5">
              <TableCell className="text-blue-400 hover:underline cursor-pointer font-mono text-xs">
                {row.orgUrl}
              </TableCell>
              <TableCell className="text-white font-semibold">
                {row.score}
              </TableCell>
              <TableCell className="text-gray-300">{row.label}</TableCell>
              <TableCell className="text-gray-300">{row.country}</TableCell>
              <TableCell className="text-gray-400 text-xs">{row.firstSeen}</TableCell>
              <TableCell className="text-gray-400 text-xs font-mono">
                {row.timeSeen}
              </TableCell>
              <TableCell className="text-gray-300 text-xs">{row.timeStamp}</TableCell>
              <TableCell>
                <Badge
                  variant={getVerdictVariant(row.verdict)}
                  className={
                    row.verdict === "High Risk"
                      ? "bg-[#E50914] hover:bg-[#E50914]/90"
                      : row.verdict === "Suspicious"
                      ? "bg-yellow-600 hover:bg-yellow-600/90"
                      : "bg-blue-600 hover:bg-blue-600/90"
                  }
                >
                  {row.verdict}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};
