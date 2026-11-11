# Build with the verified M1 publication folder as the context.
FROM rayproject/ray@sha256:e93e502244bf8c0ecf8c633099f7819d7c973d76eded8e32617e1fb66725da02
COPY --chown=ray:users ray.lock /opt/kryvola/ray.lock
RUN python -m venv --system-site-packages /home/ray/kryvola
COPY --chown=ray:users kryvola_fabric_ray-*.whl /opt/kryvola/
RUN /home/ray/kryvola/bin/python -m pip install --require-hashes -r /opt/kryvola/ray.lock && /home/ray/kryvola/bin/python -m pip install --no-deps /opt/kryvola/*.whl
ENV PATH="/home/ray/kryvola/bin:${PATH}"
