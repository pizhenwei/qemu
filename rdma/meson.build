rdma_ss.add([files(
  'rdmadev.c',
  'rdma-utils.c',
)])

#subdir('ibdev')
subdir('roce')

rdma_ss = rdma_ss.apply(config_host, strict: false)

rdma_modules = {}

modules += { 'rdma': rdma_modules }
