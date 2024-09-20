from openai import AzureOpenAI, OpenAI
from pydantic import BaseModel

def send_message(openai_data: dict, prompt_input: str, prompt_system_message: str, response_model: type[BaseModel]) -> dict:
    print(f"Inside the send_message function")

    api_key = openai_data.get("openai_api_key")
    api_base = openai_data.get("openai_base_url")
    api_version = openai_data.get("openai_version")
    deployment_name = openai_data.get("openai_deployment_name")

    if api_version:
        print(f"We have an API version, and so we are in Azure")

        client = AzureOpenAI(
            api_key=api_key,
            azure_endpoint=api_base,
            api_version=api_version
        )
    else:
        print("We are not in Azure")

        client = OpenAI(
            api_key=api_key,
            base_url=api_base
        )

    try:
        response = client.beta.chat.completions.parse(
            model=deployment_name,
            temperature=0.2,
            messages=[
                {"role": "system", "content": prompt_system_message},
                {"role": "user", "content": prompt_input}
            ],
            response_format=response_model
        )
        json_response = response.choices[0].message.parsed.dict()

        print(f"This is the response from OpenAI: {json_response}")

        if json_response:
            return json_response
        else:
            return {
                'status_code': 500,
                'detail': 'An error occurred, no response was received from OpenAI.'
            }
    except Exception as e:
        return {
            'status_code': 500,
            'detail': f"An error occurred while trying to receive a response from OpenAI: {e}"
        }
