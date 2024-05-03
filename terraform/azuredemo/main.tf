provider "azurerm" {
  features {}
  region = "East US"
}


resource "azurerm_virtual_network" "blog_vnet" {
  name                = "blogVNet"
  address_space       = ["10.0.0.0/16"]
  location            = "East US"
  resource_group_name = azurerm_resource_group.blog_rg.name
}


resource "azurerm_subnet" "blog_subnet" {
  name                 = "blogSubnet"
  resource_group_name  = azurerm_resource_group.blog_rg.name
  virtual_network_name = azurerm_virtual_network.blog_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}


resource "azurerm_network_security_group" "blog_nsg" {
  name                = "blogNSG"
  location            = "East US"
  resource_group_name = azurerm_resource_group.blog_rg.name

  security_rule {
    name                       = "SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}


resource "azurerm_linux_virtual_machine" "blog_vm" {
  name                = "blogVM"
  resource_group_name = azurerm_resource_group.blog_rg.name
  location            = "East US"
  size                = "Standard_B1s"
  admin_username      = "adminuser"
  network_interface_ids = [azurerm_network_interface.blog_nic.id]
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  disable_password_authentication = true
}


resource "azurerm_network_interface" "blog_nic" {
  name                = "blogNIC"
  location            = "East US"
  resource_group_name = azurerm_resource_group.blog_rg.name

  ip_configuration {
    name                          = "blogNICConfig"
    subnet_id                     = azurerm_subnet.blog_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.blog_pip.id
  }
}


resource "azurerm_public_ip" "blog_pip" {
  name                = "blogPublicIP"
  location            = "East US"
  resource_group_name = azurerm_resource_group.blog_rg.name
  allocation_method   = "Dynamic"
}


resource "azurerm_postgresql_server" "blog_db" {
  name                = "exampleblogdb"
  location            = "East US"
  resource_group_name = azurerm_resource_group.blog_rg.name
  sku_name            = "B_Gen5_1"
  storage_mb          = 5120
  backup_retention_days = 7
  geo_redundant_backup = "Disabled"
  auto_grow_enabled    = false
  version              = "11"
  administrator_login          = "dbadmin"
  administrator_login_password = "securepassword"
  ssl_enforcement_enabled      = false
}


resource "azurerm_storage_account" "blog_storage" {
  name                     = "exampleblogstorage"
  resource_group_name      = azurerm_resource_group.blog_rg.name
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Allow"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.blog_subnet.id]
    bypass                     = ["Logging", "Metrics"]
  }

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "public_container" {
  name                  = "publiccontainer"
  storage_account_name  = azurerm_storage_account.blog_storage.name
  container_access_type = "container"
}
