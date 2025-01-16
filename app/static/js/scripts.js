document.addEventListener("DOMContentLoaded", () => {
    const scanButton = document.getElementById("scan-image");
    const scanOutput = document.getElementById("scan-output");
    const reportButton = document.getElementById("generate-report");

    // Trigger Trivy scan
    scanButton.addEventListener("click", async () => {
        const imageName = document.getElementById("image-name").value;
        if (!imageName) {
            alert("Please enter a Docker image name.");
            return;
        }

        scanOutput.textContent = "Scanning...";

        try {
            const response = await fetch("/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ image_name: imageName }),
            });

            if (!response.ok) throw new Error("Failed to perform scan.");

            const result = await response.json();
            scanOutput.textContent = JSON.stringify(result, null, 2);
        } catch (error) {
            scanOutput.textContent = `Error: ${error.message}`;
        }
    });

    // Trigger report generation
    reportButton.addEventListener("click", async () => {
        const scanOutputText = scanOutput.textContent;
        if (!scanOutputText || scanOutputText.startsWith("Error") || scanOutputText === "Scanning...") {
            alert("Run a successful scan first!");
            return;
        }

        const cveList = JSON.parse(scanOutputText);

        try {
            const response = await fetch("/generate-report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ cve_list: cveList }), // Pass actual CVE list
            });

            if (!response.ok) throw new Error("Failed to generate report.");

            const result = await response.json();
            alert(`Report generated! Download it from: ${result.pdf}`);
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });
});