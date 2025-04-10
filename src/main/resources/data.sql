CREATE TABLE IF NOT EXISTS AUTHORIZED_IPS (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL
);

INSERT INTO AUTHORIZED_IPS (ip_address) VALUES ('127.0.0.1');
INSERT INTO AUTHORIZED_IPS (ip_address) VALUES ('0:0:0:0:0:0:0:1');
INSERT INTO AUTHORIZED_IPS (ip_address) VALUES ('192.168.1.100');
