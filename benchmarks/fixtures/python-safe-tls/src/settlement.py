import requests


def settle_payment(request, service_token):
    response = requests.post(
        "https://payments.example.internal/settle",
        headers={"Authorization": f"Bearer {service_token}"},
        json={"amount": request.body["amount"]},
        verify=True,
        timeout=5,
    )
    return response.json()
