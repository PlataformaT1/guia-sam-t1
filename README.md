# Guía Completa: Desarrollo Serverless con AWS SAM e Infraestructura Existente

Esta guía detallada te llevará paso a paso desde la instalación de herramientas hasta el despliegue automatizado de una aplicación serverless en AWS utilizando el Modelo de Aplicación Serverless (SAM), aprovechando infraestructura existente e implementando un sistema de Integración Continua/Despliegue Continuo (CI/CD) seguro con GitHub Actions.

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [Arquitectura del Sistema](#2-arquitectura-del-sistema)
3. [Prerrequisitos](#3-prerrequisitos)
4. [Instalación de Herramientas](#4-instalación-de-herramientas)
5. [Creación del Proyecto SAM](#5-creación-del-proyecto-sam)
   - [Estructura del Proyecto](#51-estructura-del-proyecto)
   - [Configuración de template.yaml](#52-configuración-de-templateyaml)
   - [Desarrollo del Código Lambda](#53-desarrollo-del-código-lambda)
6. [Configuración del Repositorio GitHub](#6-configuración-del-repositorio-github)
   - [Inicializar el Repositorio](#61-inicializar-el-repositorio)
   - [Configurar Variables y Secretos](#62-configurar-variables-y-secretos)
   - [Configurar GitHub Actions](#63-configurar-github-actions)
7. [Preparación de la Infraestructura AWS](#7-preparación-de-la-infraestructura-aws)
   - [Configurar OIDC para GitHub Actions](#71-configurar-oidc-para-github-actions)
   - [Crear Rol IAM para Despliegue](#72-crear-rol-iam-para-despliegue)
   - [Recopilar Información de la Infraestructura Existente](#73-recopilar-información-de-la-infraestructura-existente)
8. [Pruebas Locales](#8-pruebas-locales)
9. [Proceso de Despliegue](#9-proceso-de-despliegue)
   - [Despliegue Manual](#91-despliegue-manual)
   - [Despliegue Automatizado](#92-despliegue-automatizado)
10. [Solución de Problemas Comunes](#10-solución-de-problemas-comunes)
11. [Monitoreo y Logs](#11-monitoreo-y-logs)
12. [Limpieza de Recursos](#12-limpieza-de-recursos)

## 1. Introducción

El enfoque de esta guía es aprovechar infraestructura existente de AWS para nuevos desarrollos serverless. Esto permite una integración fluida con sistemas actuales y reduce la duplicación de recursos. Trabajaremos específicamente con:

- **AWS Lambda** para la lógica de negocio
- **API Gateway existente** (REST o HTTP) para exponer endpoints
- **VPC existente** con subredes y grupos de seguridad
- **Layers de Lambda existentes** para dependencias comunes
- **MongoDB Atlas** como base de datos
- **GitHub Actions con OIDC** para CI/CD seguro

Este enfoque es ideal para organizaciones que ya cuentan con una infraestructura AWS establecida y desean añadir nuevas funcionalidades sin reinventar la rueda.

## 2. Arquitectura del Sistema

La arquitectura de nuestra aplicación serverless sigue este patrón:

* **Desarrollo Local**: Escribes código en tu máquina y lo pruebas localmente con SAM CLI
* **Control de Versiones**: El código se versiona en GitHub
* **CI/CD Pipeline**: Al hacer push, GitHub Actions ejecuta pruebas y despliega a AWS usando OIDC
* **Infraestructura AWS Existente**: 
  * Lambda: Ejecuta tu código de negocio
  * API Gateway: Existente, proporciona endpoints HTTP
  * VPC: Existente, provee aislamiento de red
  * Security Groups: Existentes, controlan el tráfico de red
  * Lambda Layers: Existentes, contienen dependencias compartidas como pymongo
* **Base de Datos**: MongoDB Atlas (externa a AWS)
* **Monitoreo y Logs**: CloudWatch para observabilidad

## 3. Prerrequisitos

Antes de comenzar, necesitarás:

1. **Cuenta de AWS** con acceso a:
   - API Gateway existente (REST o HTTP)
   - VPC existente con subredes y security groups
   - Lambda Layer existente con dependencias (pymongo, etc.)

2. **Cuenta de GitHub** para alojar el código y configurar GitHub Actions

3. **Cuenta de MongoDB Atlas** (o cualquier otro servicio de base de datos)

4. **Permisos de AWS** para:
   - Crear/modificar roles IAM
   - Crear proveedores de identidad OIDC
   - Desplegar funciones Lambda
   - Modificar API Gateway existente
   - Crear secretos en AWS Secrets Manager

## 4. Instalación de Herramientas

Instala las herramientas necesarias según tu sistema operativo:

### Windows

```bash
# Instalar Python 3.11 (descargar desde python.org)
# Asegúrate de marcar "Add Python to PATH" durante la instalación

# Verificar instalación de Python
python --version

# Instalar AWS CLI (descargar instalador MSI desde aws.amazon.com)
aws --version

# Instalar AWS SAM CLI (descargar instalador MSI desde GitHub)
sam --version

# Configurar credenciales AWS (para desarrollo local)
aws configure
```

### macOS

```bash
# Instalar Homebrew si no está instalado
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar Python 3.11
brew install python@3.11

# Instalar AWS CLI
brew install awscli

# Instalar AWS SAM CLI
brew tap aws/tap
brew install aws-sam-cli

# Configurar credenciales AWS (para desarrollo local)
aws configure
```

### Linux (Ubuntu/Debian)

```bash
# Actualizar paquetes
sudo apt update

# Instalar Python 3.11
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Instalar AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Instalar AWS SAM CLI
wget https://github.com/aws/aws-sam-cli/releases/latest/download/aws-sam-cli-linux-x86_64.zip
unzip aws-sam-cli-linux-x86_64.zip -d sam-installation
sudo ./sam-installation/install

# Configurar credenciales AWS (para desarrollo local)
aws configure
```

## 5. Creación del Proyecto SAM

### 5.1 Estructura del Proyecto

Inicializa un nuevo proyecto SAM:

```bash
# Inicializar proyecto SAM
sam init --runtime python3.11 --name mi-proyecto-serverless --app-template hello-world
cd mi-proyecto-serverless
```

O usa el asistente interactivo:

```bash
sam init
```

Selecciona:
- Template: AWS Quick Start Templates
- Runtime: Python 3.11
- Package type: Zip
- Name: mi-proyecto-serverless
- Template: Hello World Example

### 5.2 Configuración de template.yaml

Reemplaza el archivo `template.yaml` generado con una versión adaptada para usar infraestructura existente:

```bash
cat > template.yaml << EOL
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  Aplicación Serverless que utiliza infraestructura AWS existente

Globals:
  Function:
    Timeout: 10
    MemorySize: 256
    Tracing: Active
    Environment:
      Variables:
        LOG_LEVEL: INFO

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, test, stage, prod]
    Description: Entorno de despliegue

  MongoDbUri:
    Type: String
    NoEcho: true
    Description: URI de conexión a MongoDB Atlas

  DatabaseName:
    Type: String
    Default: sampledb
    Description: Nombre de la base de datos MongoDB

  CollectionName:
    Type: String
    Default: samples
    Description: Nombre de la colección MongoDB

  ApiGatewayType:
    Type: String
    Default: http
    AllowedValues: [http, rest]
    Description: Tipo de API Gateway existente

  ExistingApiId:
    Type: String
    Description: ID de la API Gateway existente

  ExistingApiStageName:
    Type: String
    Default: dev
    Description: Nombre del stage de la API Gateway existente

  ExistingVpcId:
    Type: String
    Description: ID de la VPC existente

  ExistingSubnetIds:
    Type: CommaDelimitedList
    Description: Lista separada por comas de IDs de subredes existentes

  ExistingSecurityGroupId:
    Type: String
    Description: ID del grupo de seguridad existente

  ExistingLayerArn:
    Type: String
    Description: ARN de la capa (layer) existente con las dependencias

Mappings:
  EnvironmentMap:
    dev:
      LogLevel: DEBUG
      MemorySize: 128
      Timeout: 10
    test:
      LogLevel: DEBUG
      MemorySize: 128
      Timeout: 10
    stage:
      LogLevel: INFO
      MemorySize: 256
      Timeout: 15
    prod:
      LogLevel: WARN
      MemorySize: 512
      Timeout: 30

Conditions:
  IsRestApi: !Equals [!Ref ApiGatewayType, "rest"]
  IsHttpApi: !Equals [!Ref ApiGatewayType, "http"]

Resources:
  # Secreto para MongoDB
  MongoDBSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub '${AWS::StackName}-mongodb-${Environment}'
      Description: Credenciales de MongoDB
      SecretString: !Sub '{"uri": "${MongoDbUri}"}'

  # Función Lambda
  HelloWorldFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub '${AWS::StackName}-${Environment}'
      CodeUri: hello_world/
      Handler: app.lambda_handler
      Runtime: python3.11
      Architectures: [x86_64]
      MemorySize: !FindInMap [EnvironmentMap, !Ref Environment, MemorySize]
      Timeout: !FindInMap [EnvironmentMap, !Ref Environment, Timeout]
      Environment:
        Variables:
          MONGODB_SECRET_ARN: !Ref MongoDBSecret
          DB_NAME: !Ref DatabaseName
          COLLECTION_NAME: !Ref CollectionName
          ENVIRONMENT: !Ref Environment
          LOG_LEVEL: !FindInMap [EnvironmentMap, !Ref Environment, LogLevel]
      VpcConfig:
        SecurityGroupIds:
          - !Ref ExistingSecurityGroupId
        SubnetIds: !Ref ExistingSubnetIds
      Layers:
        - !Ref ExistingLayerArn
      Policies:
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - ec2:CreateNetworkInterface
                - ec2:DescribeNetworkInterfaces
                - ec2:DeleteNetworkInterface
              Resource: "*"
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
                - secretsmanager:DescribeSecret
              Resource: !Ref MongoDBSecret

  # Grupo de logs para Lambda
  HelloWorldFunctionLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${HelloWorldFunction}'
      RetentionInDays: 7

  # Integración con API Gateway HTTP existente
  ApiGatewayIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Condition: IsHttpApi
    Properties:
      ApiId: !Ref ExistingApiId
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${HelloWorldFunction.Arn}/invocations'
      PayloadFormatVersion: '2.0'
      IntegrationMethod: POST

  # Ruta para API Gateway HTTP
  # Usamos una ruta única para evitar conflictos con rutas existentes
  ApiGatewayRoute:
    Type: AWS::ApiGatewayV2::Route
    Condition: IsHttpApi
    Properties:
      ApiId: !Ref ExistingApiId
      RouteKey: 'GET /hello-new'
      Target: !Sub 'integrations/${ApiGatewayIntegration}'

  # Permiso para que API Gateway invoque la función Lambda
  ApiGatewayPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref HelloWorldFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/*/hello-new'

Outputs:
  HelloWorldFunction:
    Description: ARN de la función Lambda
    Value: !GetAtt HelloWorldFunction.Arn
  
  ApiEndpoint:
    Description: URL del endpoint
    Value: !Sub 'https://${ExistingApiId}.execute-api.${AWS::Region}.amazonaws.com/${ExistingApiStageName}/hello-new'
EOL
```

### 5.3 Desarrollo del Código Lambda

Actualiza el archivo `hello_world/app.py` con código que se conecte a MongoDB:

```bash
cat > hello_world/app.py << EOL
import json
import os
import logging
import time
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

# Importa pymongo desde el layer (no necesitamos incluirlo en requirements.txt)
import pymongo
from pymongo import MongoClient

# Configuración de logging
logger = logging.getLogger()
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logger.setLevel(log_level)

# Variables para reutilización de conexiones entre invocaciones
mongo_client = None
last_connection_time = 0
connection_ttl = 300  # 5 minutos

def get_mongodb_uri():
    """Obtiene la URI de MongoDB, ya sea de variable de entorno directa o de Secrets Manager"""
    # Si hay configurada una URI directa, usarla
    direct_uri = os.environ.get('MONGODB_URI')
    if direct_uri:
        return direct_uri
    
    # Si no, intentar obtenerla de Secrets Manager
    secret_name = os.environ.get('MONGODB_SECRET_ARN')
    if not secret_name:
        raise ValueError("No se encontró MONGODB_URI ni MONGODB_SECRET_ARN")
    
    # Obtener secreto de AWS Secrets Manager
    region = os.environ.get('AWS_REGION', 'us-east-1')
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region)
    
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response['SecretString']
        secret_data = json.loads(secret_string)
        return secret_data.get('uri')
    except ClientError as e:
        logger.error(f"Error al obtener secreto: {str(e)}")
        raise

def get_mongodb_client():
    """Obtiene un cliente MongoDB reutilizable"""
    global mongo_client, last_connection_time
    current_time = time.time()
    
    # Si no hay cliente o ha expirado, crear uno nuevo
    if mongo_client is None or (current_time - last_connection_time) > connection_ttl:
        mongodb_uri = get_mongodb_uri()
        logger.debug(f"Conectando a MongoDB...")
        mongo_client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        last_connection_time = current_time
        logger.info("Conexión a MongoDB creada o renovada")
    
    return mongo_client

def lambda_handler(event, context):
    """Función principal del Lambda"""
    # Registrar inicio de ejecución
    request_id = context.aws_request_id if context else 'local'
    start_time = time.time()
    
    logger.info(json.dumps({
        "request_id": request_id,
        "event": "request_started",
        "timestamp": datetime.utcnow().isoformat(),
        "path": event.get('path', ''),
        "method": event.get('httpMethod', '')
    }))
    
    try:
        # Obtener cliente MongoDB
        client = get_mongodb_client()
        
        # Nombres de base de datos y colección
        db_name = os.environ.get('DB_NAME', 'sampledb')
        collection_name = os.environ.get('COLLECTION_NAME', 'samples')
        
        # Acceder a la colección
        db = client[db_name]
        collection = db[collection_name]
        
        # Verificar conexión con MongoDB
        server_info = client.server_info()
        doc_count = collection.count_documents({})
        
        # Ejemplo: insertar documento de prueba si no hay
        if doc_count == 0:
            test_doc = {
                "test": True,
                "message": "Hello World",
                "timestamp": datetime.utcnow().isoformat()
            }
            collection.insert_one(test_doc)
            doc_count = 1
            logger.info("Documento de prueba insertado")
        
        # Registrar tiempo de ejecución
        elapsed_time = (time.time() - start_time) * 1000
        logger.info(json.dumps({
            "request_id": request_id,
            "event": "request_completed",
            "duration_ms": round(elapsed_time, 2)
        }))
        
        # Respuesta exitosa
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "message": "Hello World",
                "mongodb_version": server_info.get('version', 'desconocida'),
                "document_count": doc_count,
                "database": db_name,
                "collection": collection_name,
                "aws_request_id": request_id,
                "execution_time_ms": round(elapsed_time, 2)
            })
        }
    except Exception as e:
        # Registrar error
        elapsed_time = (time.time() - start_time) * 1000
        error_msg = str(e)
        logger.error(json.dumps({
            "request_id": request_id,
            "event": "request_failed",
            "error": error_msg,
            "duration_ms": round(elapsed_time, 2)
        }))
        
        # Respuesta de error
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "error": "Error al conectar con MongoDB",
                "details": error_msg,
                "aws_request_id": request_id
            })
        }
EOL
```

Actualiza también el archivo `hello_world/requirements.txt` para desarrollo local:

```bash
cat > hello_world/requirements.txt << EOL
boto3==1.26.0
pymongo==4.5.0
dnspython==2.4.2
EOL
```

## 6. Configuración del Repositorio GitHub

### 6.1 Inicializar el Repositorio

Ahora que ya tienes tu proyecto SAM creado, configura Git y conéctalo a GitHub:

```bash
# Inicializar repositorio Git
git init

# Crear archivo .gitignore
cat > .gitignore << EOL
# Python
__pycache__/
*.py[cod]
*.so
.Python
venv/
env/

# AWS SAM
.aws-sam/
samconfig.toml
packaged.yaml

# Entorno
.env
env.json

# IDE
.idea/
.vscode/
*.swp
EOL

# Añadir archivos y hacer el primer commit
git add .
git commit -m "Inicialización del proyecto SAM"

# Conectar con GitHub (reemplaza con tu URL real)
git remote add origin https://github.com/USUARIO_GITHUB/NOMBRE_REPO.git
git push -u origin main o master, dependiendo del repo
```

### 6.2 Configurar Variables y Secretos

En GitHub, debes configurar variables y secretos para el workflow de despliegue:

1. **Crear un entorno en GitHub**:
   - Ve a tu repositorio en GitHub
   - Haz clic en "Settings" → "Environments" → "New environment"
   - Nombra el entorno (ej. "dev", "prod")

2. **Configura variables de entorno**:
   - En la configuración del entorno, haz clic en "Environment variables"
   - Añade las siguientes variables:
     - `AWS_ROLE_ARN`: ARN del rol IAM (formato: `arn:aws:iam::CUENTA_AWS:role/NOMBRE_ROL`)
     - `AWS_REGION`: Región AWS (ej. `us-east-1`)
     - `STACK_NAME`: Nombre base del stack (ej. `mi-proyecto-serverless`)
     - `ENVIRONMENT`: Entorno (ej. `dev`)
     - `DATABASE_NAME`: Nombre de la base de datos
     - `COLLECTION_NAME`: Nombre de la colección
     - `API_GATEWAY_TYPE`: Tipo de API Gateway (http o rest)
     - `EXISTING_API_ID`: ID de API Gateway existente
     - `EXISTING_API_STAGE_NAME`: Nombre del stage (ej. `dev`)
     - `EXISTING_VPC_ID`: ID de VPC existente
     - `EXISTING_SUBNET_IDS`: IDs de subredes separados por comas
     - `EXISTING_SECURITY_GROUP_ID`: ID del grupo de seguridad
     - `EXISTING_LAYER_ARN`: ARN del layer existente

3. **Configura secretos**:
   - En la configuración del entorno, haz clic en "Environment secrets"
   - Añade el siguiente secreto:
     - `MONGODB_URI`: URI de conexión a MongoDB Atlas

### 6.3 Configurar GitHub Actions

Crea un archivo de workflow para GitHub Actions:

```bash
# Crear directorio para workflows
mkdir -p .github/workflows

# Crear archivo de workflow (sin backslashes problemáticos)
cat > .github/workflows/deploy.yml << EOL
name: Deploy Serverless Application

on:
  push:
    branches: [main, master ,develop, 'release/*']
  pull_request:
    branches: [main, master ,develop]

permissions:
  id-token: write  # Necesario para OIDC
  contents: read   # Necesario para checkout

jobs:
  test-and-deploy:
    runs-on: ubuntu-latest
    environment: ${{ github.ref == 'refs/heads/main' && 'prod' || github.ref == 'refs/heads/develop' && 'dev' || startsWith(github.ref, 'refs/heads/release/') && 'stage' || 'test' }}
    
    steps:
      # Debug para verificar la configuración
      - name: Debug Environment Variables
        run: |
          echo "GitHub Variables:"
          echo "AWS_ROLE_ARN: ${{ vars.AWS_ROLE_ARN }}"
          echo "AWS_REGION: ${{ vars.AWS_REGION }}"
          echo "STACK_NAME: ${{ vars.STACK_NAME }}"
          echo "ENVIRONMENT: ${{ vars.ENVIRONMENT }}"
          
          echo "GitHub Context Information:"
          echo "Repository: ${{ github.repository }}"
          echo "Branch: ${{ github.ref }}"
          echo "Workflow: ${{ github.workflow }}"

      - name: Checkout repository
        uses: actions/checkout@v3
      
      - name: Set up Python 3.11
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest pytest-mock boto3
          pip install -r hello_world/requirements.txt
          
      - name: Run tests
        run: |
          python -m pytest tests/unit/
          
      - name: Check and delete failed stack if needed
        if: github.event_name == 'push'
        run: |
          # Check if stack exists and is in a failed state
          STACK_STATUS=$(aws cloudformation describe-stacks --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "STACK_NOT_FOUND")
          
          # If stack is in a failed state, delete it
          if [[ $STACK_STATUS == *"FAILED"* || $STACK_STATUS == *"ROLLBACK"* ]]; then
            echo "Stack is in $STACK_STATUS state. Deleting..."
            aws cloudformation delete-stack --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }}
            aws cloudformation wait stack-delete-complete --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }}
            echo "Stack deleted successfully."
          elif [[ $STACK_STATUS != "STACK_NOT_FOUND" ]]; then
            echo "Stack exists and is in $STACK_STATUS state."
          else
            echo "Stack does not exist yet."
          fi
          
      - name: Install AWS SAM CLI
        if: github.event_name == 'push'
        run: |
          pip install aws-sam-cli
          
      - name: Configure AWS credentials with OIDC
        if: github.event_name == 'push'
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          
      - name: Build with SAM
        if: github.event_name == 'push'
        run: |
          sam build
          
      - name: Deploy with SAM
        if: github.event_name == 'push'
        run: |
          sam deploy --no-confirm-changeset --no-fail-on-empty-changeset --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} --resolve-s3 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides Environment=${{ vars.ENVIRONMENT }} MongoDbUri=${{ secrets.MONGODB_URI }} DatabaseName=${{ vars.DATABASE_NAME }} CollectionName=${{ vars.COLLECTION_NAME }} ApiGatewayType=${{ vars.API_GATEWAY_TYPE }} ExistingApiId=${{ vars.EXISTING_API_ID }} ExistingApiStageName=${{ vars.EXISTING_API_STAGE_NAME }} ExistingVpcId=${{ vars.EXISTING_VPC_ID }} ExistingSubnetIds=${{ vars.EXISTING_SUBNET_IDS }} ExistingSecurityGroupId=${{ vars.EXISTING_SECURITY_GROUP_ID }} ExistingLayerArn=${{ vars.EXISTING_LAYER_ARN }}
EOL
```

## 7. Preparación de la Infraestructura AWS

### 7.1 Configurar OIDC para GitHub Actions

El protocolo OpenID Connect (OIDC) permite que GitHub Actions se autentique directamente con AWS sin necesidad de almacenar credenciales de larga duración:

1. **Crear un proveedor de identidad OIDC en AWS**:
   - Inicia sesión en la consola AWS y navega a IAM → Identity providers → Add provider
   - Selecciona "OpenID Connect"
   - Provider URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
   - Haz clic en "Add provider"

### 7.2 Crear Rol IAM para Despliegue

El rol IAM determina qué acciones puede realizar GitHub Actions en tu cuenta AWS:

1. **Crear un nuevo rol IAM**:
   - En IAM, crea un nuevo rol con la opción "Web identity"
   - Selecciona el proveedor OIDC de GitHub que acabas de crear
   - Para "Audience", selecciona `sts.amazonaws.com`

2. **Configura la política de confianza del rol**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::CUENTA_AWS:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
           },
           "StringLike": {
             "token.actions.githubusercontent.com:sub": "repo:USUARIO_GITHUB/NOMBRE_REPO:*"
           }
         }
       }
     ]
   }
   ```
   - Reemplaza `CUENTA_AWS` con tu ID de cuenta AWS
   - Reemplaza `USUARIO_GITHUB/NOMBRE_REPO` con tu nombre de usuario/organización y nombre de repositorio en GitHub 

3. **Agrega políticas de permisos** al rol:
   - `CloudFormationFullAccess` - Para crear/actualizar stacks 
   - `AWSLambdaFullAccess` - Para gestionar funciones Lambda
   - `AmazonAPIGatewayAdministrator` - Para gestionar API Gateway
   - `IAMFullAccess` - Para gestionar roles IAM
   - `CloudWatchLogsFullAccess` - ¡IMPORTANTE! Para crear y gestionar grupos de logs
   - `AmazonVPCFullAccess` - Para acceder a recursos VPC
   - `SecretsManagerReadWrite` - Para gestionar secretos
   - `AmazonS3FullAccess` - SAM usa S3 para almacenar artefactos

   En producción, deberías limitar estas políticas siguiendo el principio de mínimo privilegio.

### 7.3 Recopilar Información de la Infraestructura Existente

Reúne información sobre los recursos existentes que utilizarás:

1. **VPC y componentes de red**:
   ```bash
   # Obtener ID de VPC
   aws ec2 describe-vpcs --query "Vpcs[*].[VpcId,Tags[?Key=='Name'].Value]" --output table

   # Obtener IDs de subredes (preferiblemente privadas)
   aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-12345678" \
     --query "Subnets[*].[SubnetId,AvailabilityZone,Tags[?Key=='Name'].Value]" --output table

   # Obtener ID de security group
   aws ec2 describe-security-groups --filters "Name=vpc-id,Values=vpc-12345678" \
     --query "SecurityGroups[*].[GroupId,GroupName,Description]" --output table
   ```

2. **API Gateway existente**:
   ```bash
   # Para API Gateway HTTP (recomendado)
   aws apigatewayv2 get-apis --query "Items[*].[ApiId,Name,ApiEndpoint]" --output table

   # Para API REST tradicional
   aws apigateway get-rest-apis --query "items[*].[id,name]" --output table
   ```

3. **Lambda Layer existente**:
   ```bash
   # Listar layers disponibles
   aws lambda list-layers --query "Layers[*].[LayerName,LayerArn]" --output table

   # Obtener versiones de un layer específico (para pymongo, etc.)
   aws lambda list-layer-versions --layer-name nombre-layer --query "LayerVersions[*].[LayerVersionArn]" --output table
   ```

Guarda toda esta información; la necesitarás para configurar tu proyecto SAM.

## 8. Pruebas Locales

Antes de desplegar, puedes probar localmente usando SAM CLI:

```bash
# Crear archivo env.json para variables locales
cat > env.json << EOL
{
  "Parameters": {
    "Environment": "dev",
    "MongoDbUri": "mongodb+srv://usuario:contraseña@cluster.mongodb.net/nombre_db",
    "DatabaseName": "nombre_db",
    "CollectionName": "nombre_coleccion",
    "ApiGatewayType": "http",
    "ExistingApiId": "api-id",
    "ExistingApiStageName": "dev",
    "ExistingVpcId": "vpc-id",
    "ExistingSubnetIds": "subnet-id1,subnet-id2",
    "ExistingSecurityGroupId": "sg-id",
    "ExistingLayerArn": "arn:aws:lambda:region:account-id:layer:nombre-layer:1"
  }
}
EOL

# Construir la aplicación
sam build

# Invocar la función directamente
sam local invoke HelloWorldFunction --env-vars env.json

# O iniciar la API local
sam local start-api --env-vars env.json

# Probar la API local
curl http://localhost:3000/hello-new
```

## 9. Proceso de Despliegue

### 9.1 Despliegue Manual

Para desplegar manualmente desde tu máquina local:

```bash
# Despliegue guiado (primera vez)
sam deploy --guided

# Despliegues subsecuentes usando configuración guardada
sam deploy

# O especificando parámetros
sam deploy --stack-name mi-proyecto-serverless-dev \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=dev \
    MongoDbUri=mongodb+srv://usuario:contraseña@cluster.mongodb.net/nombre_db \
    DatabaseName=nombre_db \
    CollectionName=nombre_coleccion \
    ApiGatewayType=http \
    ExistingApiId=api-id \
    ExistingApiStageName=dev \
    ExistingVpcId=vpc-id \
    ExistingSubnetIds=subnet-id1,subnet-id2 \
    ExistingSecurityGroupId=sg-id \
    ExistingLayerArn=arn:aws:lambda:region:account-id:layer:nombre-layer:1
```

### 9.2 Despliegue Automatizado

Para desplegar automáticamente usando GitHub Actions:

1. **Configurar variables y secretos** en GitHub como se describió anteriormente
2. **Push a la rama configurada** para activar el workflow:

```bash
# Ejemplo: push a la rama develop
git checkout -b develop
git push --set-upstream origin develop
```

3. **Verificar el progreso** en la pestaña "Actions" de tu repositorio GitHub
4. **Revisar los logs** para identificar posibles errores

## 10. Solución de Problemas Comunes

### Problema: Error de OIDC - "Not authorized to perform sts:AssumeRoleWithWebIdentity"

**Causa**: La política de confianza del rol IAM no está correctamente configurada para GitHub Actions.

**Solución**:
1. Verifica la configuración exacta del proveedor OIDC
2. Actualiza la política de confianza del rol IAM asegurando:
   - El ARN del proveedor OIDC es correcto
   - La condición `StringLike` para `token.actions.githubusercontent.com:sub` coincide exactamente con tu repositorio
   - La condición para la rama es correcta si estás restringiendo por rama

### Problema: Error CloudWatch Logs - "logs:CreateLogGroup"

**Causa**: El rol IAM no tiene permisos para gestionar grupos de logs en CloudWatch.

**Solución**:
1. Añade la política `CloudWatchLogsFullAccess` al rol IAM
2. O añade los permisos específicos:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "logs:CreateLogGroup",
       "logs:DeleteLogGroup",
       "logs:CreateLogStream",
       "logs:PutLogEvents"
     ],
     "Resource": "arn:aws:logs:*:*:*"
   }
   ```

### Problema: "Stack is in ROLLBACK_FAILED state and can not be updated"

**Causa**: Un despliegue anterior falló y dejó el stack en un estado que no permite actualizaciones.

**Solución**:
1. Elimina manualmente el stack fallido:
   ```bash
   aws cloudformation delete-stack --stack-name nombre-stack-dev
   aws cloudformation wait stack-delete-complete --stack-name nombre-stack-dev
   ```
2. Despliega nuevamente

### Problema: "Route with key GET /hello already exists for this API"

**Causa**: La ruta que estás intentando crear ya existe en la API Gateway existente.

**Solución**:
1. Usa una ruta diferente en tu template:
   ```yaml
   ApiGatewayRoute:
     # ...
     Properties:
       # ...
       RouteKey: 'GET /hello-new'  # Usa un nombre único
   ```
2. Actualiza también el permiso de Lambda y cualquier otro recurso relacionado

### Problema: Variables de Entorno Vacías en GitHub Actions

**Causa**: Las variables no están configuradas correctamente o el workflow no tiene acceso al entorno.

**Solución**:
1. Verifica que el workflow especifique el entorno correcto:
   ```yaml
   jobs:
     deploy:
       # ...
       environment: dev  # Debe coincidir con el nombre del entorno
   ```
2. Confirma que las variables estén configuradas en el entorno correcto en GitHub

## 11. Monitoreo y Logs

Una vez desplegada tu aplicación, puedes monitorearla:

### Ver Logs

```bash
# Ver logs recientes de la función Lambda
aws logs get-log-events --log-group-name /aws/lambda/mi-proyecto-serverless-dev --log-stream-name "YYYY/MM/DD/[$LATEST]XXXXXXXXX"

# O usando SAM
sam logs --stack-name mi-proyecto-serverless-dev --name HelloWorldFunction --tail
```

### Monitoreo en CloudWatch

1. **Accede a CloudWatch Dashboards** para una vista general
2. **Configura alarmas** para detectar problemas:
   ```bash
   aws cloudwatch put-metric-alarm \
     --alarm-name "LambdaErrorAlarm" \
     --metric-name Errors \
     --namespace AWS/Lambda \
     --statistic Sum \
     --period 60 \
     --evaluation-periods 1 \
     --threshold 1 \
     --comparison-operator GreaterThanOrEqualToThreshold \
     --dimensions Name=FunctionName,Value=mi-proyecto-serverless-dev \
     --alarm-actions arn:aws:sns:us-east-1:CUENTA_AWS:AlarmTopic
   ```

### Prueba de Endpoint

Prueba el endpoint de tu API usando:

```bash
curl https://api-id.execute-api.region.amazonaws.com/stage/hello-new
```

## 12. Limpieza de Recursos

Si necesitas eliminar los recursos creados:

```bash
# Eliminar stack usando SAM
sam delete --stack-name mi-proyecto-serverless-dev

# O directamente con CloudFormation
aws cloudformation delete-stack --stack-name mi-proyecto-serverless-dev

# Eliminar secreto de Secrets Manager (opcional)
aws secretsmanager delete-secret --secret-id mi-proyecto-serverless-mongodb-dev --recovery-window-in-days 7
```

---

Esta guía detallada te permite aprovechar infraestructura existente en AWS para desarrollar y desplegar aplicaciones serverless de manera eficiente, utilizando las mejores prácticas de CI/CD con GitHub Actions y OIDC para una autenticación segura sin credenciales de larga duración.

La combinación de AWS SAM, infraestructura existente y CI/CD automatizado te ofrece:

- Desarrollo rápido y enfocado en la lógica de negocio
- Reutilización de componentes existentes
- Despliegue automatizado y seguro
- Facilidad de pruebas y monitoreo

Siguiendo los pasos de esta guía, podrás implementar un flujo de trabajo profesional para el desarrollo serverless que se integra perfectamente con tu infraestructura AWS actual.