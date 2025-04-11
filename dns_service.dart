Future<void> main() async {
  print('DNS Service is starting...');

  // 模拟 DNS 服务的运行逻辑
  try {
    while (true) {
      print('DNS Service is running...');
      await Future.delayed(Duration(seconds: 5)); // 模拟服务处理
    }
  } catch (e, stackTrace) {
    print('DNS Service encountered an error: $e');
    print('Stack trace: $stackTrace'); // 添加堆栈信息以便调试
  } finally {
    print('DNS Service is shutting down...');
  }
}
