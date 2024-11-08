# Vagrantfile
NUM_VMS = 100

Vagrant.configure("2") do |config|
  # Create the pensim network if it doesn't exist
  system('docker network create --subnet=10.0.1.0/24 pensim || true')

  config.ssh.username = "student"
  config.ssh.password = "student"
  config.ssh.insert_key = false

  # Disable default synced folder
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.allow_fstab_modification = false
  config.vm.allow_hosts_modification = false

  (1..NUM_VMS).each do |i|
    config.vm.define "student_#{i}" do |node|
      node.vm.provider "docker" do |docker|
        docker.name = "student_#{i}"
        docker.build_dir = "."  # Directory containing Dockerfile
        docker.volumes = ["student_#{i}_home:/home/student"]
        docker.create_args = [
          "--hostname=student#{i}",
          "--network=pensim",
          "--ip=10.0.1.#{i+10}"  # Will give IPs from 10.0.1.11 to 10.0.1.110
        ]
      end
    end
  end
end
