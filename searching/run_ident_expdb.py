import json
import re
from agno.tools.base import Tool


class IdentifierTool(Tool):
	def __init__(self):
		super().__init__(
			name="identifier",
			description="Extracts and formats relevant CVE information from JSON for PoC identification"
		)

	def call(self, cve_file_path: str) -> str:
		"""
		Load and extract essential CVE fields to help LLM understand and identify a PoC.

		Args:
			cve_file_path (str): Path to CVE JSON file from NVD.

		Returns:
			str: Human-readable JSON-like string used as LLM input.
		"""
		try:
			with open(cve_file_path, "r", encoding="utf-8") as f:
				data = json.load(f)

			cve_item = data["vulnerabilities"][0]["cve"]
			cve_id = cve_item.get("id", "")
			description = cve_item.get("descriptions", [{}])[0].get("value", "")
			references = [r["url"] for r in cve_item.get("references", [])]

			cvss_v3 = cve_item.get("metrics", {}).get("cvssMetricV31", [])
			cvss_summary = []
			for m in cvss_v3:
				d = m.get("cvssData", {})
				cvss_summary.append({
					"source": m.get("source", ""),
					"baseScore": d.get("baseScore", ""),
					"vectorString": d.get("vectorString", ""),
					"severity": d.get("baseSeverity", "")
				})

			weaknesses = [w["description"][0]["value"] for w in cve_item.get("weaknesses", []) if "description" in w]

			result = {
				"CVE ID": cve_id,
				"Description": description,
				"CVSS v3 Summary": cvss_summary,
				"Weaknesses": weaknesses,
				"References": references
			}

			return self._clean_json_block(json.dumps(result, indent=2))

		except Exception as e:
			return f"[ERROR] Failed to parse CVE file: {e}"

	def _clean_json_block(self, text: str) -> str:
		"""
		Ensure the returned JSON is not wrapped in markdown formatting.

		Args:
			text (str): Raw text possibly wrapped in markdown

		Returns:
			str: Cleaned JSON string
		"""
		match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
		return match.group(1).strip() if match else text.strip()
