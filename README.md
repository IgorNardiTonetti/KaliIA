# AI Kali Assistant

Bot local em Python com interface Tkinter para conversar com o Ollama, usar o modelo `qwen3:14b` por padrão e executar ações autorizadas em uma VM Kali Linux via SSH.

## Recursos

- Interface desktop simples com Tkinter.
- Layout em dois painéis: conversa à esquerda e Execução Kali/Terminal à direita.
- Divisores arrastáveis para ajustar a largura dos painéis e o tamanho de conversa, mensagem, decisão operacional e terminal.
- Botão **Configurar** no topo para abrir Ollama, SSH e regras.
- Chat com IA via `http://localhost:11434/api/chat`.
- Resposta em streaming no chat, sem esperar a geração inteira terminar.
- Botão **Parar** para interromper geração do Ollama.
- Modelo padrão `qwen3:14b`, escolhido por seguir melhor formatos operacionais rígidos.
- Contexto limitado e saída maior para manter o desktop mais responsivo.
- Aviso explícito quando a resposta atinge o limite de tamanho.
- Status com tempo decorrido e etapa atual enquanto Ollama ou SSH trabalham.
- Inicialização automática do `ollama serve` quando a API local não estiver ativa.
- Modelo padrão `qwen3:14b`.
- Edição das regras do sistema pelo botão **Definir Regras**.
- Regras salvas em `rules.txt` e enviadas literalmente como a única mensagem de sistema para o modelo.
- Configurações salvas em `config.json`.
- Teste de conexão com Ollama com aquecimento real do modelo.
- Teste de conexão SSH com Kali usando Paramiko.
- Painel de decisão operacional preparado pela IA.
- Execução automática no Kali para ações leves permitidas.
- Correção automática quando a IA responde com procedimento, markdown ou ação solta sem `ACAO_KALI`.
- Aceita variações operacionais como `ACAOKALI:`, `ACAO KALI:`, `ACAO1:`/`AÇÃO 1:` e ignora achados declarados antes de saída real do terminal.
- Runner inicial de avaliação web para URLs, cobrindo headers, CORS, cookies, HTML, scripts, endpoints em JS, sourcemaps e paths comuns antes de entregar evidências à IA.
- Saída SSH em tempo real enquanto a ação roda.
- Análise automática da saída SSH pela IA depois que uma ação termina.
- Proteção anti-loop contra sequências fracas de `curl | grep` sem evidência.
- Bloqueio automático de ações destrutivas, shells reversos, payloads e ações intensas como brute force/wordlists.
- Logs em `logs/`.
- Relatórios em Markdown em `reports/`.

## Requisitos

- Python 3.10 ou superior.
- Ollama instalado e rodando localmente.
- Modelo `qwen3:14b` baixado no Ollama.
- VM Kali Linux com SSH ativo e acessível pela máquina host.

## Instalação

No terminal, entre na pasta do projeto:

```bash
cd ai-kali-assistant
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

Baixe o modelo padrão no Ollama, se ainda não tiver:

```bash
ollama pull qwen3:14b
```

O app tenta iniciar o Ollama automaticamente quando necessário. Se preferir iniciar manualmente:

```bash
ollama serve
```

Se a inicialização automática falhar, veja `logs/ollama-serve.log`.

## Executar

```bash
python main.py
```

## Uso básico

1. Clique em **Configurar** no topo.
2. Preencha IP do Kali, usuário SSH, senha SSH e modelo Ollama.
3. Clique em **Salvar Configurações**.
4. Clique em **Testar Ollama** para validar a API local e aquecer o modelo antes do primeiro chat.
5. Clique em **Testar SSH Kali** para validar o acesso à VM.
6. Converse com a IA pelo campo de chat.
7. Peça uma análise, por exemplo: `analise o site autorizado https://exemplo.com/login`.
8. Para URLs, o app começa com uma avaliação web estruturada automática e coleta evidências reais.
9. A IA toma decisões operacionais e o app executa automaticamente no Kali quando a ação for permitida.
10. Cada retorno aparece no terminal Kali inferior e é enviado automaticamente para a IA analisar a continuidade.
11. Use **Relatório** para gerar um Markdown em `reports/`.

O modelo `qwen3:14b` pode demorar no primeiro carregamento. Depois que carrega, o app mantém o modelo ativo por aproximadamente 30 minutos. Enquanto ele gera, a barra de progresso e o status mostram a etapa atual, e o botão **Parar** permite interromper a geração. Se a resposta bater no limite de tamanho, o chat mostra um aviso e você pode enviar `continue`.

O arquivo `Modelfile.whiterabbitneo-ptbr` fica no projeto como alternativa local baseada no WhiteRabbitNeo V3 15 GB.

O arquivo `Modelfile.deephat-v1-ptbr` fica no projeto como alternativa local baseada no DeepHat V1 15 GB.

O arquivo `Modelfile.deephat` fica no projeto como alternativa local baseada em `qwen3:14b`.

## Segurança e escopo

Este assistente foi feito para atividades autorizadas de segurança, como reconhecimento permitido, análise de resultados, geração de relatórios e correção de falhas. O modo atual executa automaticamente ações leves decididas pela IA, mas bloqueia ações destrutivas, payloads, shells reversos e ações intensas como brute force ou enumeração agressiva por wordlist.

As regras padrão ficam em `rules.txt` e podem ser alteradas no botão **Definir Regras**. O app não injeta regras fixas no prompt do modelo: o conteúdo de `rules.txt` é a fonte de regras enviada à IA.
