FROM scratch
USER 99
ADD whois42d /
CMD ["/whois42d", "-registry", "/registry", "-port", "4343"]
