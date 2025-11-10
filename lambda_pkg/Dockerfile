FROM public.ecr.aws/lambda/python:3.13

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

# Copy your Lambda function code
COPY lambda_function.py ${LAMBDA_TASK_ROOT}

# Set the handler
CMD [ "lambda_function.lambda_handler" ]
