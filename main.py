import os
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
import time
import json # Importa a biblioteca JSON para formatar a resposta
import uuid

# >>> NOVO BLOCO DE LOGGING <<<
import logging
import http.client as http_client

# Habilita o logging de debug para o tráfego HTTP/HTTPS
http_client.HTTPConnection.debuglevel = 1

# Configurações básicas de log para imprimir detalhes no console
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG) 
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
# >>> FIM DO NOVO BLOCO DE LOGGING <<<


# 1. Carregar Variáveis de Ambiente
load_dotenv()

# Variáveis de Configuração
CLIENT_ID = os.getenv("SANTANDER_CLIENT_ID")
CLIENT_SECRET = os.getenv("SANTANDER_CLIENT_SECRET")
AUTH_URL = os.getenv("SANTANDER_AUTH_URL")
CERT_PATH = os.getenv("CERT_PATH")
CERT_PASSWORD = os.getenv("CERT_PASSWORD")
PIX_URL = os.getenv("SANTANDER_PIX_URL") # Deve ser o endpoint de Pagamento Pix
WORKSPACE_ID = os.getenv("WORKSPACE_ID") # Novo ID de Workspace necessário

# --- Funções de Ajuda para Segurança e mTLS ---

def get_session_with_mtls():
    """Cria uma sessão requests configurada com o certificado mTLS."""
    session = requests.Session()
    
    # A sessão usa o caminho do certificado PEM (que contém chave e certificado)
    try:
        session.cert = CERT_PATH 
        # A API de pagamentos (v1) não usa o 'scope' na requisição de token,
        # mas a permissão deve estar configurada no Client ID no portal.
        print("✅ Sessão requests configurada com certificado (mTLS).")
        return session
    except Exception as e:
        print(f"❌ Erro ao configurar o certificado para a sessão: {e}")
        print("VERIFIQUE: Se o CERT_PATH aponta para o arquivo .pem.")
        return None

def get_access_token():
    """Obtém o Access Token usando OAuth 2.0 e mTLS."""
    session = get_session_with_mtls()
    if not session:
        return None

    # Payload para obter o token (Sem 'scope' aparente na coleção de Pagamentos)
    payload = {
        'grant_type': 'client_credentials'
    }
    
    # Autenticação Basic (ID/Secret)
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    
    try:
        response = session.post(
            AUTH_URL,
            auth=auth,
            data=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10 
        )
        response.raise_for_status() 

        token_data = response.json()
        print("✅ Token obtido com sucesso!")
        return token_data.get('access_token')

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na requisição de autenticação (API Santander): {e}")
        if 'response' in locals() and response.text:
            print(f"Detalhes da Resposta da API: {response.text}")
        return None

# --- FUNÇÃO PARA ENVIAR PIX IMEDIATO ---

def send_pix_payment(token, pix_url_final, pix_data, cert_path, client_id):
    """
    Inicia o pagamento Pix usando o endpoint Management Payments Partners.
    """
    
    # Cabeçalhos confirmados na Coleção de Pagamentos
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        # Cabeçalho para identificação da aplicação
        'X-Application-Key': client_id, 
        # ID de correlação para rastreamento (boa prática)
        'X-Correlation-ID': 'CORR_' + str(int(time.time())), 
    }
    
    try:
        print(f"\n➡️ Iniciando Pagamento Pix para: {pix_url_final}")
        
        response = requests.post(
            pix_url_final,
            headers=headers,
            json=pix_data,
            cert=cert_path, # Certificado mTLS para Produção
            timeout=15
        )
        response.raise_for_status() 
        
        print("✅ Requisição de Pagamento Pix enviada. Verificando status...")
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao iniciar Pagamento Pix: {e}")
        
        if 'response' in locals() and response.text:
            # Imprimir o erro JSON da API
            try:
                error_details = response.json()
                print(f"Detalhes da Resposta da API (Erro): {json.dumps(error_details, indent=4)}")
            except json.JSONDecodeError:
                print(f"Resposta bruta da API: {response.text}")
             
        if 'response' in locals():
             print(f"Status Code: {response.status_code}")
             
        return None

# main.py (Adicionar esta nova função)

def confirm_pix_payment(token, workspace_id, pix_payment_id, cert_path, client_id):
    """
    Confirma o pagamento Pix iniciado, alterando o status para AUTHORIZED via PATCH.
    """
    PATCH_BASE_URL = PIX_URL + "/:pix_payment_id"
    # URL para confirmação (PATCH /workspaces/{ws_id}/pix_payments/{pix_id})
    # PIX_URL contém a primeira parte. Substituímos o {ws_id} e adicionamos o pix_id.
    CONFIRM_URL = PATCH_BASE_URL.replace(":workspace_id", workspace_id)
    CONFIRM_URL = CONFIRM_URL.replace(":pix_payment_id", pix_payment_id)
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-Application-Key': client_id, 
        'X-Correlation-ID': 'CORR_CONFIRM_' + str(int(time.time())), 
    }

    # Payload para autorizar o débito
    confirmation_payload = {
        "paymentValue": "0.01", # O valor deve ser o mesmo do pagamento iniciado
        "debitAccount": {
            "branch": "3457",   # Sua Agência (A mesma usada na criação do Workspace)
            "number": "000130039016" # Seu Número de Conta PJ
        },
        "status": "AUTHORIZED" # Status para confirmar a transação
    }
    
    print(f"\n➡️ Confirmando Pagamento (PATCH) para ID: {pix_payment_id}")
    
    try:
        response = requests.patch(
            CONFIRM_URL,
            headers=headers,
            json=confirmation_payload,
            cert=cert_path,
            timeout=15
        )
        response.raise_for_status() 
        
        print("✅ Confirmação enviada. Verificando resultado...")
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao confirmar Pagamento Pix: {e}")
        # ... (Lógica de tratamento de erro)
        if 'response' in locals() and response.text:
            try:
                error_details = response.json()
                print(f"Detalhes da Resposta da API (Erro): {json.dumps(error_details, indent=4)}")
            except json.JSONDecodeError:
                print(f"Resposta bruta da API: {response.text}")
        return None

def create_workspace(token, cert_path, client_id):
    """
    Tenta criar o Workspace. Se falhar por 409 (já existe), chama a consulta.
    """
    
    BASE_WORKSPACE_URL = PIX_URL.split("/workspaces")[0] + "/workspaces"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-Application-Key': client_id, 
        'X-Correlation-ID': 'CORR_WS_CREATE_' + str(int(time.time())), 
    }
    # main.py (Modificação na função create_workspace)

    # ...
    
    workspace_data = {
        "type": "PAYMENTS", 
        "description": "Meu Pix API Simples", # Máx. 30 caracteres
        
        "mainDebitAccount": {
            "branch": "3457",  # <-- SUA AGÊNCIA (como string)
            "number": "000130039016" # <-- SEU NÚMERO DE CONTA PJ (como string)
        },
        
        # Campos adicionais do exemplo CURL (para garantir a validação)
        "additionalDebitAccounts": [], # Deixar vazio se não tiver
        "tags": [
            "api-pix-python",
            "prod-test"
        ],
        "webhookURL": "https://example.com/webhook",
        
        # ATIVANDO TODOS OS TIPOS DE PAGAMENTO (COMO NO EXEMPLO)
        "pixPaymentsActive": True,
        "bankSlipPaymentsActive": True,
        "barCodePaymentsActive": True,
        "taxesByFieldPaymentsActive": True,
        "vehicleTaxesPaymentsActive": True,
        "bankTransferPaymentsActive": True,
        "bankSlipAvailableActive": True,
        "bankSlipAvailableWebhookActive": True,
        "smartTransfersActive": True
    }
    
    # ... (o restante da função)
    
    print(f"\n➡️ Tentando criar o Workspace ID em: {BASE_WORKSPACE_URL}")

    try:
        response = requests.post(
            BASE_WORKSPACE_URL,
            headers=headers,
            json=workspace_data,
            cert=cert_path,
            timeout=15
        )
        response.raise_for_status() 

        ws_data = response.json()
        new_ws_id = ws_data.get('id')
        
        if new_ws_id:
            print(f"✅ WORKSPACE ID OBTIDO/CRIADO com sucesso: {new_ws_id}")
            print(f"⚠️ AÇÃO: COPIE este ID e cole no seu arquivo .env na variável WORKSPACE_ID para futuras execuções.")
            return new_ws_id
        # ... (restante da lógica de sucesso)

    except requests.exceptions.HTTPError as e:
        # Se retornar 409 Conflict (já existe) ou 400 (se o Santander estiver mal-configurado):
        if 'response' in locals() and (response.status_code == 409 or response.status_code == 400): 
            print("⚠️ Criação do Workspace falhou (Pode ser que já exista ou erro de permissão/dados iniciais).")
            # CHAMAR FUNÇÃO DE CONSULTA
            return consult_workspace(token, cert_path, client_id, BASE_WORKSPACE_URL)
        
        # ... (restante da lógica de erro)
        return None

# --- NOVA FUNÇÃO PARA CONSULTAR O ID EXISTENTE ---

def consult_workspace(token, cert_path, client_id, base_workspace_url):
    """
    Consulta a lista de Workspaces para encontrar o ID existente.
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Application-Key': client_id,
        'X-Correlation-ID': 'CORR_WS_CONSULT_' + str(int(time.time())), 
    }
    
    print(f"➡️ Tentando consultar Workspaces em: {base_workspace_url}")
    
    try:
        response = requests.get(
            base_workspace_url, # GET no endpoint base
            headers=headers,
            cert=cert_path,
            timeout=15
        )
        response.raise_for_status()
        
        consult_data = response.json()
        workspaces = consult_data.get('items', [])
        
        if workspaces:
            # Pega o ID do primeiro Workspace da lista
            ws_id = workspaces[0].get('id')
            print(f"✅ WORKSPACE EXISTENTE ENCONTRADO! ID: {ws_id}")
            print("⚠️ AÇÃO: Cole este ID no seu arquivo .env na variável WORKSPACE_ID.")
            return ws_id
        else:
            print("❌ NENHUM WORKSPACE ENCONTRADO na sua conta.")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao consultar Workspaces: {e}")
        return None

# Não se esqueça de colocar o 'import json' no topo!
    
# --- Lógica Principal ---
if __name__ == "__main__":
    
    token = get_access_token()

    if token:
        
        current_workspace_id = WORKSPACE_ID
        
        # --- (Aqui entra o código que cria o Workspace, se necessário) ---
        # ATENÇÃO: Seu log mais recente já criou o Workspace com sucesso.
        # Se você inseriu o ID (2ec0fe09-d097-46ab-a6a0-b6773250eee2) no .env,
        # o código vai pular a criação.
        # -------------------------------------------------------------------

        # 2. Continua com o envio do Pix (Usando o ID obtido/existente)
        print("\n==================================")
        print("SEGUNDA ETAPA: INICIANDO PAGAMENTO PIX")
        print("==================================")
        
        PIX_URL_FINAL = PIX_URL.replace(":workspace_id", current_workspace_id)
        
        # --- PAYLOAD PARA PAGAMENTO PIX IMEDIATO ---
        pix_info = {
            "id": str(uuid.uuid4()), # ID Único no formato UUID
            "tags": ["API", "PRIMEIRO_PIX"],
            "paymentValue": "0.01", 
            "remittanceInformation": "Pagamento de teste via API",
            "dictCode": "deposito@mb.com.br", 
            "dictCodeType": "EMAIL"
        }
        
        pix_response = send_pix_payment(
            token, 
            PIX_URL_FINAL, 
            pix_info, 
            CERT_PATH, 
            CLIENT_ID 
        )

        if pix_response:
            pix_payment_id = pix_response.get('id')
            
            print("\n✅ SUCESSO na INICIAÇÃO! Pix está em status READY_TO_PAY.")
            
            # --- 3. CONFIRMAR O PAGAMENTO ---
            print("\n==================================")
            print("TERCEIRA ETAPA: CONFIRMANDO PAGAMENTO (DEBITO)")
            print("==================================")
            
            confirm_response = confirm_pix_payment(
                token, 
                current_workspace_id, 
                pix_payment_id, 
                CERT_PATH, 
                CLIENT_ID
            )
            
            if confirm_response:
                 print("\n✅ SUCESSO FINAL: Pagamento confirmado/autorizado!")
                 print(json.dumps(confirm_response, indent=4))
        
    else:
        print("\nNão foi possível obter o Access Token. Verifique credenciais e permissões.")