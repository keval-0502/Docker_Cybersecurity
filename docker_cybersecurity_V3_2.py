from http import client
import docker
from datetime import datetime
import hashlib
import getpass
import subprocess

def pull_and_run_httpd(container_name):
    # Connect to the Docker daemon
    client = docker.from_env()
    try:
        # Pull httpd image from Docker Hub
        client.images.pull("httpd:latest")
        # Run httpd image and map ports
        container = client.containers.run("httpd:latest", detach=True, ports={'80/tcp': 8080}, name=container_name)
        print(f"Container '{container_name}' running with httpd image.")
        return container
    except Exception as e:
        print(f"Error: {e}")

def modify_index_html(container, filename):
    try:
        # Path to the index.html file in the container
        index_html_path = "/usr/local/apache2/htdocs/index.html"
        # Write the new content to index.html
        container.exec_run(['sh', '-c', 'echo I am Keval Bavisi and this is my CY5001 Contapache Project on $(date) > /usr/local/apache2/htdocs/index.html'])
        print("Index.html modified successfully.")
    except Exception as e:
        print(f"Error: {e}")

def commit_and_push_image(container, docker_username, docker_password):
    try:
        # Commit changes to a new image
        new_image = container.commit()

        # Authenticate with Docker Hub using API token
        auth_token = hashlib.sha256(docker_password.encode()).hexdigest()
        client.login(username=docker_username, password=auth_token)

        # Tag the new image
        image_tag = f"{docker_username}/httpd-modified:latest"
        new_image.tag(image_tag)

        # Push the image to Docker Hub
        client.images.push(image_tag)

        print(f"Image '{image_tag}' successfully committed and pushed to Docker Hub.")

    except Exception as e:
        print(f"Error: {e}")

def implement_https(container_name):
    # Connect to the Docker daemon
    client = docker.from_env()

    try:
        # Get the running container
        container = client.containers.get(container_name)

        # Install mod_ssl for HTTPS support
        container.exec_run("apt-get update && apt-get install -y apache2 && a2enmod ssl && service apache2 restart")

        # Update Apache configuration to use the self-signed certificate
        container.exec_run("a2ensite default-ssl")
        container.exec_run("a2enmod ssl")

        # Configure Apache to use modern SSL/TLS protocols
        ssl_config_commands = [
        "SSLEngine on",
        "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
        "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        "SSLHonorCipherOrder on",
        "SSLOptions +StrictRequire",
        f"echo 'SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt' >> /etc/apache2/sites-available/default-ssl.conf",
         f"echo 'SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key' >> /etc/apache2/sites-available/default-ssl.conf",
        "echo 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"' >> /etc/apache2/sites-available/default-ssl.conf"
        ]

        # Run each command separately
        for command in ssl_config_commands:
                container.exec_run(["bash", "-c", command])

        # Restart Apache service
        container.exec_run("service apache2 restart")

        print("HTTPS configured successfully.")


        # Restart Apache service
        container.exec_run("service apache2 restart")

        print("HTTPS configured successfully.")

    except docker.errors.NotFound:
                    print(f"Container '{container_name}' not found. Make sure it is running.")

def configure_security_headers(container_name):
    # Connect to the Docker daemon
    client = docker.from_env()

    try:
        # Get the running container
        container = client.containers.get(container_name)

        # Configure security headers
        security_headers_config = """
        Header set Content-Security-Policy "script-src 'self';"
        Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
        Header set X-Content-Type-Options "nosniff"
        """
        container.exec_run(f"bash -c \"echo '{security_headers_config}' >> /etc/apache2/apache2.conf\"")
        container.exec_run("service apache2 restart")

        print("Security headers configured successfully.")

    except docker.errors.NotFound:
        print(f"Container '{container_name}' not found. Make sure it is running.")

def trivy_image_scan(base_image):
    # Run Trivy vulnerability scan on the base image
    try:
        subprocess.run(["trivy", "image", base_image], check=True)
        print("Trivy scan completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Trivy scan failed with error: {e}")

def automate_security_testing(container_name, target_url):
    # Connect to the Docker daemon
    client = docker.from_env()

    try:
        # Get the running container
        container = client.containers.get(container_name)

        # Install OWASP ZAP and start automated security testing
        container.exec_run("apt-get update && apt-get install -y zaproxy")
        container.exec_run(f"zap-cli -p 8080 quick-scan -o '-config api.disablekey=true' -t {target_url}")

        print("OWASP ZAP security testing completed successfully.")

    except docker.errors.NotFound:
        print(f"Container '{container_name}' not found. Make sure it is running.")

def network_security_monitoring(container_name):
    # Connect to the Docker daemon
    client = docker.from_env()

    try:
        # Get the running container
        container = client.containers.get(container_name)

        # Install and start Suricata for network security monitoring
        container.exec_run("apt-get update && apt-get install -y suricata")
        container.exec_run("suricata -c /etc/suricata/suricata.yaml -i eth0 -D")

        print("Suricata network security monitoring started successfully.")

    except docker.errors.NotFound:
        print(f"Container '{container_name}' not found. Make sure it is running.")

def commit_and_push_image(container_name, docker_username, docker_password):
    # Connect to the Docker daemon
    client = docker.from_env()

    try:
        # Get the running container
        container = client.containers.get(container_name)

        # Commit changes to a new image
        new_image = container.commit()

        # Authenticate with Docker Hub using API token
        auth_token = hashlib.sha256(docker_password.encode()).hexdigest()
        client.login(username=docker_username, password=auth_token)

        # Tag the new image
        image_tag = f"{docker_username}/httpd-modified:latest"
        new_image.tag(image_tag)

        # Push the image to Docker Hub
        client.images.push(image_tag)

        print(f"Image '{image_tag}' successfully committed and pushed to Docker Hub.")

    except docker.errors.NotFound:
        print(f"Container '{container_name}' not found. Make sure it is running.")

if __name__ == "__main__":
    # Replace placeholder values with your actual values
    container_name = "Pycontapache"
    docker_username = input("Enter your Docker Hub username: ")
    docker_password = getpass.getpass("Enter your Docker Hub password: ")

    # Pull and run httpd image
    filename = "foo"
    httpd_container = pull_and_run_httpd(container_name)

    # Modify index.html in the running container
    modify_index_html(httpd_container, filename)

    # Implement additional cybersecurity enhancements
    implement_https(container_name)
    configure_security_headers(container_name)
    trivy_image_scan("httpd:latest")
    automate_security_testing(container_name, "http://localhost:8080")
    network_security_monitoring(container_name)

    # Commit changes and push to Docker Hub
    commit_and_push_image(container_name, docker_username, docker_password)

    



    

