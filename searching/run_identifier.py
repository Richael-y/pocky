import sys
import os
import json

from agents.identifier_agent import IdentifierAgent
from models.openai_agent import OpenAIAgent

def save_result(cve_path: str, llm_response: str):
	"""
	Save LLM response to a result file alongside the original CVE JSON.

	Args:
		cve_path (str): Path to original CVE JSON file.
		llm_response (str): Raw output from the model.
	"""
	output_path = cve_path.replace(".json", "_result.json")
	try:
		# Try parsing as JSON if possible
		result = json.loads(llm_response)
	except Exception:
		# Fall back to raw text output
		result = {"raw_output": llm_response}
	
	with open(output_path, "w", encoding="utf-8") as f:
		json.dump(result, f, indent=2)
	
	print(f"[✓] Result saved to: {output_path}")

def main():
	if len(sys.argv) != 2:
		print("Usage: python run_identifier.py <path_to_CVE_json>")
		return

	cve_path = sys.argv[1]
	if not os.path.exists(cve_path):
		print(f"[✗] File not found: {cve_path}")
		return

	# Init GPT-4o agent
	model = OpenAIAgent(
		api_key="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",  # ← Replace with your actual API key
		base_url="https://api.openai.com/v1",
		model_name="gpt-4o"
	)

	# Run identifier agent
	agent = IdentifierAgent(model)
	llm_response = agent.run(cve_path)

	print("\n[LLM Response]:\n", llm_response)
	save_result(cve_path, llm_response)

if __name__ == "__main__":
	main()
