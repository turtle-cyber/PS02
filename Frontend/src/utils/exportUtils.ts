import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

// Interface matching the DomainItem structure from the tables
interface DomainItem {
  id: string;
  metadata: {
    registrable?: string;
    ipv4?: string | null;
    risk_score?: number;
    final_verdict?: string;
    verdict?: string;
    nameserver?: string | null;
    mx_count?: number | null;
    first_seen?: string;
    registrar?: string;
  };
}

// Utility to safely convert values to strings
const safe = (v: unknown) =>
  v === null || v === undefined || String(v).trim() === "" ? "N/A" : String(v);

// Get current date for filename
const getDateString = () => {
  const now = new Date();
  return now.toISOString().split("T")[0]; // YYYY-MM-DD format
};

// Convert data to CSV row format
const convertToCSVRow = (item: DomainItem, includeLookalikeColumns: boolean): string[] => {
  const m = item.metadata || {};
  const row = [
    safe(m.registrable),
    safe(m.ipv4),
  ];

  // Add URL Construction column only for lookalikes
  if (includeLookalikeColumns) {
    row.push("N/A"); // URL Construction not provided by API
  }

  row.push(
    String(m.risk_score ?? "N/A"),
    safe(m.final_verdict ?? m.verdict),
    safe(m.nameserver),
    String(m.mx_count ?? "N/A"),
    safe(m.first_seen),
    safe(m.registrar)
  );

  return row;
};

// Escape CSV values that contain commas, quotes, or newlines
const escapeCSVValue = (value: string): string => {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
};

/**
 * Export table data to CSV format
 */
export const exportToCSV = (
  data: DomainItem[],
  filename: string,
  reportType: "lookalikes" | "url-reports"
) => {
  const includeLookalikeColumns = reportType === "lookalikes";

  // CSV Headers
  const headers = [
    "Source URL",
    "IP Address",
    ...(includeLookalikeColumns ? ["URL Construction"] : []),
    "Risk Score",
    "Verdict",
    "Name Server",
    "MX Records",
    "Registration Date",
    "Registrar",
  ];

  // Convert data to CSV rows
  const rows = data.map((item) => convertToCSVRow(item, includeLookalikeColumns));

  // Build CSV content
  const csvContent = [
    headers.map(escapeCSVValue).join(","),
    ...rows.map((row) => row.map(escapeCSVValue).join(",")),
  ].join("\n");

  // Create blob and download
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);

  link.setAttribute("href", url);
  link.setAttribute("download", `${filename}-${getDateString()}.csv`);
  link.style.visibility = "hidden";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

/**
 * Export table data to PDF format
 */
export const exportToPDF = (
  data: DomainItem[],
  filename: string,
  reportType: "lookalikes" | "url-reports"
) => {
  const includeLookalikeColumns = reportType === "lookalikes";

  // Create PDF document
  const doc = new jsPDF({
    orientation: "landscape",
    unit: "mm",
    format: "a4",
  });

  // Add title
  const title = reportType === "lookalikes" ? "Lookalikes Report" : "URL Reports";
  doc.setFontSize(16);
  doc.text(title, 14, 15);

  // Add date
  doc.setFontSize(10);
  doc.text(`Generated on: ${new Date().toLocaleString()}`, 14, 22);

  // Headers
  const headers = [
    "Source URL",
    "IP Address",
    ...(includeLookalikeColumns ? ["URL Const."] : []),
    "Risk",
    "Verdict",
    "Name Server",
    "MX",
    "Reg. Date",
    "Registrar",
  ];

  // Convert data to table rows
  const tableData = data.map((item) => {
    const m = item.metadata || {};
    const row = [
      safe(m.registrable),
      safe(m.ipv4),
    ];

    if (includeLookalikeColumns) {
      row.push("N/A");
    }

    row.push(
      String(m.risk_score ?? "N/A"),
      safe(m.final_verdict ?? m.verdict),
      safe(m.nameserver),
      String(m.mx_count ?? "N/A"),
      safe(m.first_seen),
      safe(m.registrar)
    );

    return row;
  });

  // Generate table using autoTable
  autoTable(doc, {
    head: [headers],
    body: tableData,
    startY: 28,
    theme: "grid",
    styles: {
      fontSize: 7,
      cellPadding: 2,
      overflow: "linebreak",
    },
    headStyles: {
      fillColor: [30, 41, 59], // slate-800
      textColor: [255, 255, 255],
      fontStyle: "bold",
    },
    alternateRowStyles: {
      fillColor: [248, 250, 252], // slate-50
    },
    columnStyles: {
      0: { cellWidth: 35 }, // Source URL
      1: { cellWidth: 25 }, // IP Address
      2: { cellWidth: includeLookalikeColumns ? 20 : 15 }, // URL Construction or Risk
      3: { cellWidth: 15 }, // Risk or Verdict
      4: { cellWidth: 20 }, // Verdict or Name Server
      5: { cellWidth: 30 }, // Name Server or MX
      6: { cellWidth: 12 }, // MX or Reg. Date
      7: { cellWidth: 22 }, // Reg. Date or Registrar
      8: { cellWidth: 30 }, // Registrar (only if lookalikes)
    },
    margin: { top: 28 },
  });

  // Add footer with page numbers
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.text(
      `Page ${i} of ${pageCount}`,
      doc.internal.pageSize.width / 2,
      doc.internal.pageSize.height - 10,
      { align: "center" }
    );
  }

  // Save PDF
  doc.save(`${filename}-${getDateString()}.pdf`);
};
