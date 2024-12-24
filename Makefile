PROTOC := protoc
PROTO_SRC := ./v3/api/v1
PROTO_OUT := ./v3/internal/services
PROTO_FILES := $(wildcard $(PROTO_SRC)/*.proto)

.PHONY: all clean

all: $(PROTO_FILES)
	@for proto in $(PROTO_FILES); do \
		$(PROTOC) --proto_path=$(PROTO_SRC) --go_out=$(PROTO_OUT) --go-grpc_out=$(PROTO_OUT) $$proto; \
	done
	@echo "Proto files compiled successfully."

clean:
	@find $(PROTO_OUT) -name '*.pb.go' -type f -delete
	@echo "Generated files cleaned."
