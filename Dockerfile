FROM archlinux:latest
RUN pacman --noconfirm -Sy make git gcc mingw-w64-gcc
WORKDIR /mnt
CMD [ "make", "all" ]