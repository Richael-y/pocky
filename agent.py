import os
import json
import time
from typing import Optional, List, Dict
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.reasoning import ReasoningTools
from agno.tools.exa import ExaTools
from agno.tools.duckduckgo import DuckDuckGoTools
from agno.team import Team
from exa_py import Exa
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import requests

class PoCky:
    def __init__(self):
        load_dotenv()
        self.exa = Exa(api_key=os.getenv("EXA_API_KEY"))
        
        # Get model configuration
        model = OpenAIChat(
            id='gpt-4o', 
            api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Create search agent
        self.search_agent = Agent(
            name="SearchAgent",
            model=model,
            tools=[
                ReasoningTools(add_instructions=True),
                ExaTools(
                    include_domains=["github.com", "exploit-db.com", "packetstormsecurity.com", "cve.org"],
                    num_results=5,
                    text_length_limit=1000,
                )
            ],
            instructions=self._load_instructions("prompts/search.txt"),
            expected_output="""
            Return results in JSON format, including "success", "step", and "PoC" fields.
            """,
            markdown=True,
            show_tool_calls=True,
            exponential_backoff=True  # Add exponential backoff retry
        )
        
        # Create attack intent analysis agent
        self.attack_intent_agent = Agent(
            name="AttackIntentAgent",
            model=model,
            tools=[
                ReasoningTools(add_instructions=True),
                ExaTools(
                    include_domains=["cve.org", "nvd.nist.gov", "cvedetails.com"],
                    num_results=3,
                    text_length_limit=1000,
                )
            ],
            instructions=self._load_instructions("prompts/attack-intent.txt"),
            expected_output="""
            Return analysis of the attack intent of the CVE, including the attacker's goals and exploitation mechanisms.
            """,
            markdown=True,
            show_tool_calls=True,
            exponential_backoff=True  # Add exponential backoff retry
        )
        
        # Create validation agent
        self.validation_agent = Agent(
            name="ValidationAgent",
            model=model,
            tools=[ReasoningTools(add_instructions=True)],
            instructions=self._load_instructions("prompts/validation.txt"),
            expected_output="""
            Return results in JSON format, including "valid" and "reasoning" fields.
            """,
            markdown=True,
            show_tool_calls=True,
            exponential_backoff=True  # Add exponential backoff retry
        )
        
        # Create team workflow
        self.team = Team(
            name="PoCkyTeam",
            mode="coordinate",
            model=model,
            members=[
                self.search_agent,
                self.attack_intent_agent,
                self.validation_agent
            ],
            instructions=[
                "You are a professional security research team focused on collecting and verifying PoC for CVE vulnerabilities.",
                "The workflow is as follows:",
                "1. First, use the SearchAgent to search for relevant PoC samples based on the CVE ID.",
                "2. Then, use the AttackIntentAgent to analyze the attack intent of the CVE.",
                "3. Finally, use the ValidationAgent to verify whether the found PoC matches the attack intent.",
                "The output of each step will be used as input for the next step.",
                "Note: If the search for PoC samples fails, you can still proceed with the attack intent analysis.",
                "If PoC samples cannot be obtained, you can skip the validation step and directly provide the attack intent analysis results."
            ],
            success_criteria="Successfully analyze the attack intent of the CVE and collect and verify related PoC samples as much as possible",
            markdown=True,
            show_tool_calls=True,
            enable_agentic_context=True,  # Enable agentic context
            share_member_interactions=True,  # Share interactions between members
        )
    
    def _load_instructions(self, file_path: str) -> str:
        """Load the content of the instruction file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            print(f"Failed to load instruction file {file_path}: {e}")
            # Return a default instruction to avoid crashing the entire program
            return "Analyze the specified CVE vulnerability."
    
    def process_cve(self, cve_id: str):
        """Process a specific CVE ID and return the final result"""
        # Execute team workflow
        try:
            result = self.team.run(f"Analyze and verify PoC for {cve_id}")
            return result
        except Exception as e:
            print(f"Error occurred while processing {cve_id}: {e}")
            # Return error information
            return {"error": str(e)}
    
    def run_workflow(self, cve_id: str, stream=True, max_retries=3):
        """Run the complete workflow and output the result"""
        print(f"Starting to process {cve_id}...")
        
        retries = 0
        while retries < max_retries:
            try:
                self.team.print_response(f"Analyze and verify PoC for {cve_id}", 
                                        stream=stream, 
                                        show_full_reasoning=True, 
                                        stream_intermediate_steps=True)
                break  # Exit loop on success
            except Exception as e:
                retries += 1
                print(f"Error occurred while running workflow (attempt {retries}/{max_retries}): {e}")
                if retries < max_retries:
                    # Wait for a while before retrying
                    wait_time = 2 ** retries  # Exponential backoff
                    print(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print("Reached maximum retry attempts, unable to complete workflow.")
                    # Attempt to run attack intent analysis separately
                    try:
                        print("\nAttempting to run attack intent analysis separately...")
                        self.attack_intent_agent.print_response(f"Analyze attack intent for {cve_id}", 
                                                              stream=stream, 
                                                              show_full_reasoning=True)
                    except Exception as intent_error:
                        print(f"Error occurred while running attack intent analysis: {intent_error}")
                        print("Please check API keys and network connection.")