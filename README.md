# Automode

This project utilizes Docker Compose for easy setup and deployment.

## Prerequisites

- Docker: [Install Docker](https://docs.docker.com/get-docker/)
- Docker Compose: [Install Docker Compose](https://docs.docker.com/compose/install/)

## Setup Instructions

1. Clone the repository:
```bash
git clone https://github.com/your-username/project-name.git
```
2. Navigate to the project directory:
```bash
cd project-name
```
3. Copy your Frontend code in `frontend` directory
4. Add .env and other environment files accordingly
5. Build and start the Docker containers using Docker Compose:
```bash
docker-compose up -d
```
   This command will download the necessary Docker images and start the containers in the background.

6. Access the application:

- Open your web browser and go to [http://localhost](http://localhost).
- To access the FastAPI list documentation, go to [http://localhost:8000/docs](http://localhost:8000/docs).

7. Stop the Docker containers:
```bash
docker-compose down
```
   This command will stop and remove the Docker containers.

## Configuration

You can modify the configuration of the application by editing the `docker-compose.yml` file and environment variables defined within. Make sure to restart the Docker containers after any changes.

